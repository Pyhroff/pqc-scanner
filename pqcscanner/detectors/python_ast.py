"""AST-based detector for Python source files.

Detects imports and calls involving quantum-broken or classically-broken
cryptographic primitives. Deliberately does NOT flag AES-256 or SHA-256/SHA-3,
which remain quantum-safe at current security parameters.

Three detection mechanisms:
  1. ImportFrom where (module, imported_name) matches a known bad pair
  2. ImportFrom where module path starts with a known bad module prefix
  3. Call-site detection for hashlib.md5 / hashlib.sha1 patterns
"""

import ast
from pathlib import Path

from pqcscanner.taxonomy import Bucket, Finding, Severity

# ── (module, imported_name) pairs that indicate quantum-broken crypto ──────────
# Covers the common `from X import Y` style.
_QB_FROM_PAIRS: dict[tuple[str, str], tuple[str, str]] = {
    # cryptography.io — from ...asymmetric import rsa/ec/dh/dsa/...
    ("cryptography.hazmat.primitives.asymmetric", "rsa"): (
        "RSA",
        "Replace with ML-KEM (FIPS 203) for key encapsulation or ML-DSA (FIPS 204) "
        "for signatures — liboqs-python",
    ),
    ("cryptography.hazmat.primitives.asymmetric", "ec"): (
        "ECC/ECDSA/ECDH",
        "Replace with ML-DSA (FIPS 204) for signatures or ML-KEM (FIPS 203) "
        "for key exchange — liboqs-python",
    ),
    ("cryptography.hazmat.primitives.asymmetric", "dh"): (
        "Diffie-Hellman (DH)",
        "Replace with ML-KEM (FIPS 203) for post-quantum key encapsulation — liboqs-python",
    ),
    ("cryptography.hazmat.primitives.asymmetric", "dsa"): (
        "DSA",
        "Replace with ML-DSA (FIPS 204) — liboqs-python",
    ),
    ("cryptography.hazmat.primitives.asymmetric", "ed25519"): (
        "Ed25519 (ECC-based)",
        "ECC-based signature; replace with ML-DSA (FIPS 204) for post-quantum security",
    ),
    ("cryptography.hazmat.primitives.asymmetric", "ed448"): (
        "Ed448 (ECC-based)",
        "ECC-based signature; replace with ML-DSA (FIPS 204)",
    ),
    ("cryptography.hazmat.primitives.asymmetric", "x25519"): (
        "X25519 (ECDH)",
        "Replace with ML-KEM (FIPS 203) for post-quantum key encapsulation",
    ),
    ("cryptography.hazmat.primitives.asymmetric", "x448"): (
        "X448 (ECDH)",
        "Replace with ML-KEM (FIPS 203)",
    ),
    # pycryptodome — from Crypto.PublicKey import RSA/ECC/DSA/ElGamal
    ("Crypto.PublicKey", "RSA"): (
        "RSA (pycryptodome)",
        "Replace with ML-KEM (FIPS 203) / ML-DSA (FIPS 204) via liboqs-python",
    ),
    ("Crypto.PublicKey", "ECC"): (
        "ECC (pycryptodome)",
        "Replace with ML-DSA (FIPS 204) via liboqs-python",
    ),
    ("Crypto.PublicKey", "DSA"): (
        "DSA (pycryptodome)",
        "Replace with ML-DSA (FIPS 204) via liboqs-python",
    ),
    ("Crypto.PublicKey", "ElGamal"): (
        "ElGamal",
        "Replace with ML-KEM (FIPS 203)",
    ),
}

# ── Classically-broken (module, imported_name) pairs ─────────────────────────
_CB_FROM_PAIRS: dict[tuple[str, str], tuple[str, str]] = {
    ("Crypto.Hash", "MD5"): (
        "MD5 (pycryptodome)",
        "Replace with Crypto.Hash.SHA256 or Crypto.Hash.SHA3_256",
    ),
    ("Crypto.Hash", "SHA1"): (
        "SHA-1 (pycryptodome)",
        "Replace with Crypto.Hash.SHA256 (SHA-1 broken since 2017 — SHAttered attack)",
    ),
    ("Crypto.Cipher", "DES"): (
        "DES (pycryptodome)",
        "Replace with Crypto.Cipher.AES with a 256-bit key",
    ),
    ("Crypto.Cipher", "DES3"): (
        "3DES/Triple-DES (pycryptodome)",
        "Replace with AES-256 (NIST deprecated 3DES in 2023, SP 800-131A r2)",
    ),
    ("Crypto.Cipher", "ARC4"): (
        "RC4 (pycryptodome)",
        "Replace with AES-256-GCM",
    ),
    ("Crypto.Cipher", "Blowfish"): (
        "Blowfish (pycryptodome)",
        "Replace with AES-256",
    ),
    # cryptography.io classically-broken imports
    ("cryptography.hazmat.primitives.hashes", "MD5"): (
        "MD5",
        "Replace with SHA256 or SHA3_256",
    ),
    ("cryptography.hazmat.primitives.hashes", "SHA1"): (
        "SHA-1",
        "Replace with SHA256 (broken since 2017, SHAttered attack)",
    ),
}

# ── Full module prefixes: any import FROM a path starting with these is QB ────
# Catches `from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key`
_QB_MODULE_PREFIXES: tuple[str, ...] = (
    "cryptography.hazmat.primitives.asymmetric.rsa",
    "cryptography.hazmat.primitives.asymmetric.ec",
    "cryptography.hazmat.primitives.asymmetric.dh",
    "cryptography.hazmat.primitives.asymmetric.dsa",
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    "cryptography.hazmat.primitives.asymmetric.ed448",
    "cryptography.hazmat.primitives.asymmetric.x25519",
    "cryptography.hazmat.primitives.asymmetric.x448",
    "rsa",  # standalone rsa package
)

# ── Call-site: hashlib.md5 / hashlib.sha1 ────────────────────────────────────
_HASHLIB_CB: dict[str, tuple[str, str]] = {
    "md5": (
        "MD5",
        "Replace with hashlib.sha256 or hashlib.sha3_256",
    ),
    "sha1": (
        "SHA-1",
        "Replace with hashlib.sha256 (SHA-1 broken since 2017 — SHAttered attack)",
    ),
    "sha224": (
        "SHA-224",
        "Replace with hashlib.sha256 (truncated output provides less security margin)",
    ),
}


def detect_python(path: Path, source: str) -> list[Finding]:
    """Return all crypto findings from a Python source file."""
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return []

    lines = source.splitlines()
    visitor = _CryptoVisitor(path, lines)
    visitor.visit(tree)
    return visitor.findings


def _ctx(lines: list[str], lineno: int) -> str:
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].strip()
    return ""


class _CryptoVisitor(ast.NodeVisitor):
    def __init__(self, path: Path, lines: list[str]) -> None:
        self.path = path
        self.lines = lines
        self.findings: list[Finding] = []
        self._aliases: dict[str, str] = {}  # local_name → resolved module

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""

        for alias in node.names:
            name = alias.name
            local = alias.asname or name
            self._aliases[local] = f"{module}.{name}" if module else name

            # Check (module, name) pair for quantum-broken
            if (module, name) in _QB_FROM_PAIRS:
                algo, rec = _QB_FROM_PAIRS[(module, name)]
                self.findings.append(Finding(
                    file=self.path, line=node.lineno,
                    algorithm=algo, bucket=Bucket.QUANTUM_BROKEN,
                    severity=Severity.CRITICAL,
                    context=_ctx(self.lines, node.lineno), recommendation=rec,
                ))

            # Check (module, name) pair for classically-broken
            elif (module, name) in _CB_FROM_PAIRS:
                algo, rec = _CB_FROM_PAIRS[(module, name)]
                self.findings.append(Finding(
                    file=self.path, line=node.lineno,
                    algorithm=algo, bucket=Bucket.CLASSICALLY_BROKEN,
                    severity=Severity.WARNING,
                    context=_ctx(self.lines, node.lineno), recommendation=rec,
                ))

        # Check full module path prefix (e.g. from ...asymmetric.rsa import generate_private_key)
        for prefix in _QB_MODULE_PREFIXES:
            if module == prefix or module.startswith(prefix + "."):
                algo = _algo_from_prefix(prefix)
                rec = _rec_from_prefix(prefix)
                self.findings.append(Finding(
                    file=self.path, line=node.lineno,
                    algorithm=algo, bucket=Bucket.QUANTUM_BROKEN,
                    severity=Severity.CRITICAL,
                    context=_ctx(self.lines, node.lineno), recommendation=rec,
                ))
                break

        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            module = alias.name
            local = alias.asname or module.split(".")[0]
            self._aliases[local] = module

            for prefix in _QB_MODULE_PREFIXES:
                if module == prefix or module.startswith(prefix + "."):
                    algo = _algo_from_prefix(prefix)
                    rec = _rec_from_prefix(prefix)
                    self.findings.append(Finding(
                        file=self.path, line=node.lineno,
                        algorithm=algo, bucket=Bucket.QUANTUM_BROKEN,
                        severity=Severity.CRITICAL,
                        context=_ctx(self.lines, node.lineno), recommendation=rec,
                    ))
                    break

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            obj_id = ""
            if isinstance(node.func.value, ast.Name):
                obj_id = node.func.value.id

            resolved = self._aliases.get(obj_id, obj_id)

            # hashlib.<hash>() and hashlib.new('<hash>')
            if resolved == "hashlib" or obj_id == "hashlib":
                if attr in _HASHLIB_CB:
                    algo, rec = _HASHLIB_CB[attr]
                    self.findings.append(Finding(
                        file=self.path, line=node.lineno,
                        algorithm=algo, bucket=Bucket.CLASSICALLY_BROKEN,
                        severity=Severity.WARNING,
                        context=_ctx(self.lines, node.lineno), recommendation=rec,
                    ))
                elif attr == "new" and node.args and isinstance(node.args[0], ast.Constant):
                    name = str(node.args[0].value).lower()
                    if name in _HASHLIB_CB:
                        algo, rec = _HASHLIB_CB[name]
                        self.findings.append(Finding(
                            file=self.path, line=node.lineno,
                            algorithm=algo, bucket=Bucket.CLASSICALLY_BROKEN,
                            severity=Severity.WARNING,
                            context=_ctx(self.lines, node.lineno), recommendation=rec,
                        ))

        self.generic_visit(node)


def _algo_from_prefix(prefix: str) -> str:
    _MAP = {
        "cryptography.hazmat.primitives.asymmetric.rsa": "RSA",
        "cryptography.hazmat.primitives.asymmetric.ec": "ECC/ECDSA/ECDH",
        "cryptography.hazmat.primitives.asymmetric.dh": "Diffie-Hellman (DH)",
        "cryptography.hazmat.primitives.asymmetric.dsa": "DSA",
        "cryptography.hazmat.primitives.asymmetric.ed25519": "Ed25519 (ECC-based)",
        "cryptography.hazmat.primitives.asymmetric.ed448": "Ed448 (ECC-based)",
        "cryptography.hazmat.primitives.asymmetric.x25519": "X25519 (ECDH)",
        "cryptography.hazmat.primitives.asymmetric.x448": "X448 (ECDH)",
        "rsa": "RSA (rsa package)",
    }
    return _MAP.get(prefix, "Quantum-Broken Algorithm")


def _rec_from_prefix(prefix: str) -> str:
    if "rsa" in prefix:
        return "Replace with ML-KEM (FIPS 203) for key encapsulation or ML-DSA (FIPS 204) for signatures — liboqs-python"
    if "ec" in prefix or "ed" in prefix or "x25519" in prefix or "x448" in prefix:
        return "Replace with ML-DSA (FIPS 204) for signatures or ML-KEM (FIPS 203) for key exchange — liboqs-python"
    if "dh" in prefix:
        return "Replace with ML-KEM (FIPS 203) — liboqs-python"
    if "dsa" in prefix:
        return "Replace with ML-DSA (FIPS 204) — liboqs-python"
    return "Replace with NIST PQC standard (FIPS 203/204/205) — liboqs-python"
