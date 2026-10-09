"""Alias-aware, Python-only cryptographic API inventory.

The inventory records static observations and deliberately distinguishes
algorithm-level risk from cases requiring key-size or deployment context.
It is not a complete whole-program or runtime crypto inventory.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

_QB_ASYMMETRIC = {
    "rsa": "RSA",
    "ec": "ECC/ECDSA/ECDH",
    "dh": "Diffie-Hellman",
    "dsa": "DSA",
    "ed25519": "Ed25519",
    "ed448": "Ed448",
    "x25519": "X25519",
    "x448": "X448",
}
_QB_PYCRYPTODOME = {
    "rsa": "RSA",
    "ecc": "ECC",
    "dsa": "DSA",
    "elgamal": "ElGamal",
}
_CLASSICALLY_BROKEN = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "des": "DES",
    "des3": "Triple-DES",
    "tripledes": "Triple-DES",
    "arc4": "RC4",
    "rc4": "RC4",
    "blowfish": "Blowfish",
}
_KNOWN_HASHES = {
    "sha224": "SHA-224",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "sha3_224": "SHA3-224",
    "sha3_256": "SHA3-256",
    "sha3_384": "SHA3-384",
    "sha3_512": "SHA3-512",
    "shake_128": "SHAKE-128",
    "shake_256": "SHAKE-256",
    "blake2b": "BLAKE2b",
    "blake2s": "BLAKE2s",
}
_JOSE_ALGORITHMS = {
    **{name: (f"JWT {name.upper()} (RSA)", "quantum_broken") for name in
       ("rs256", "rs384", "rs512", "ps256", "ps384", "ps512")},
    **{name: (f"JWT {name.upper()} (ECDSA)", "quantum_broken") for name in
       ("es256", "es384", "es512")},
    "eddsa": ("JWT EdDSA (Ed25519/Ed448)", "quantum_broken"),
}
_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", "build", "dist"}


def _primitive(module: str, name: str) -> tuple[str, str] | None:
    lowered = name.lower()
    if module == "cryptography.hazmat.primitives.asymmetric" and lowered in _QB_ASYMMETRIC:
        return _QB_ASYMMETRIC[lowered], "quantum_broken"
    if module == "Crypto.PublicKey" and lowered in _QB_PYCRYPTODOME:
        return _QB_PYCRYPTODOME[lowered], "quantum_broken"
    if module == "cryptography.hazmat.primitives.hashes":
        if lowered in _CLASSICALLY_BROKEN:
            return _CLASSICALLY_BROKEN[lowered], "classically_broken"
        if lowered in _KNOWN_HASHES:
            return _KNOWN_HASHES[lowered], "not_flagged_by_current_taxonomy"
    if module == "Crypto.Hash":
        if lowered in _CLASSICALLY_BROKEN:
            return _CLASSICALLY_BROKEN[lowered], "classically_broken"
        if lowered in _KNOWN_HASHES:
            return _KNOWN_HASHES[lowered], "not_flagged_by_current_taxonomy"
    if module in {"cryptography.hazmat.primitives.ciphers.algorithms", "Crypto.Cipher"}:
        if lowered in _CLASSICALLY_BROKEN:
            return _CLASSICALLY_BROKEN[lowered], "classically_broken"
        if lowered in {"aes", "chacha20", "chacha20poly1305"}:
            return name.upper(), "parameter_context_required"
    return None


def _prefix_primitive(module: str) -> tuple[str, str] | None:
    prefix_maps = (
        ("cryptography.hazmat.primitives.asymmetric.", _QB_ASYMMETRIC, "quantum_broken"),
        ("rsa.", {"rsa": "RSA"}, "quantum_broken"),
    )
    for prefix, mapping, classification in prefix_maps:
        if module.startswith(prefix):
            tail = module[len(prefix):].split(".", 1)[0].lower()
            if tail in mapping:
                return mapping[tail], classification
    return None


class _InventoryVisitor(ast.NodeVisitor):
    def __init__(self, relative_file: str, lines: list[str]) -> None:
        self.relative_file = relative_file
        self.lines = lines
        self.aliases: dict[str, str] = {}
        self.records: list[dict] = []
        self.seen: set[tuple] = set()

    def _record(self, algorithm: str, classification: str, api: str, line: int) -> None:
        key = (self.relative_file, line, algorithm, classification, api)
        if key in self.seen:
            return
        self.seen.add(key)
        self.records.append({
            "file": self.relative_file,
            "line": max(1, line),
            "algorithm": algorithm,
            "classification": classification,
            "api": api,
            "context": self.lines[line - 1].strip() if 1 <= line <= len(self.lines) else "",
        })

    def _resolve(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            parent = self._resolve(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            module = alias.name
            local = alias.asname or module.split(".")[0]
            self.aliases[local] = module
            primitive = _prefix_primitive(module)
            if primitive:
                self._record(*primitive, api=module, line=node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        module_primitive = _prefix_primitive(module)
        if module_primitive:
            self._record(*module_primitive, api=module, line=node.lineno)
        for alias in node.names:
            local = alias.asname or alias.name
            full_name = f"{module}.{alias.name}" if module else alias.name
            self.aliases[local] = full_name
            primitive = _primitive(module, alias.name)
            if primitive:
                self._record(*primitive, api=full_name, line=node.lineno)
        self.generic_visit(node)

    @staticmethod
    def _literal_strings(node: ast.AST) -> set[str]:
        values: set[str] = set()
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            values.add(node.value)
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for item in node.elts:
                values.update(_InventoryVisitor._literal_strings(item))
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and str(key.value).lower() in {"alg", "algorithm"}:
                    values.update(_InventoryVisitor._literal_strings(value))
        return values

    def visit_Call(self, node: ast.Call) -> None:
        resolved = self._resolve(node.func)
        lowered = resolved.lower()

        if lowered.startswith("hashlib."):
            name = lowered.rsplit(".", 1)[-1]
            if name == "new" and node.args:
                names = self._literal_strings(node.args[0])
            else:
                names = {name}
            for item in names:
                primitive = _primitive("hashlib", item)
                if primitive:
                    self._record(*primitive, api=resolved, line=node.lineno)

        elif lowered.startswith("crypto.hash."):
            parts = lowered.split(".")
            if len(parts) >= 4 and parts[-1] == "new":
                primitive = _primitive("Crypto.Hash", parts[-2])
                if primitive:
                    self._record(*primitive, api=resolved, line=node.lineno)

        elif lowered.startswith("cryptography.hazmat.primitives.hashes."):
            primitive = _primitive("cryptography.hazmat.primitives.hashes", lowered.rsplit(".", 1)[-1])
            if primitive:
                self._record(*primitive, api=resolved, line=node.lineno)

        elif lowered.startswith(("cryptography.hazmat.primitives.ciphers.algorithms.", "crypto.cipher.")):
            primitive = _primitive(
                "cryptography.hazmat.primitives.ciphers.algorithms"
                if lowered.startswith("cryptography.") else "Crypto.Cipher",
                lowered.split(".")[-2] if lowered.endswith(".new") else lowered.split(".")[-1],
            )
            if primitive:
                self._record(*primitive, api=resolved, line=node.lineno)

        if lowered in {"jwt.encode", "jwt.decode", "jose.jwt.encode", "jose.jwt.decode"}:
            for keyword in node.keywords:
                if keyword.arg in {"algorithm", "alg", "algorithms", "headers"}:
                    for name in self._literal_strings(keyword.value):
                        match = _JOSE_ALGORITHMS.get(name.lower())
                        if match:
                            self._record(match[0], match[1], api=f"{resolved}[{name}]", line=node.lineno)
        self.generic_visit(node)


def build_inventory(path: Path) -> dict:
    """Inventory known cryptographic API observations from Python files."""
    root = path.resolve()
    if root.is_file():
        files = [root] if root.suffix == ".py" else []
        base = root.parent
    else:
        files = [
            file for file in root.rglob("*.py")
            if not any(part in _SKIP_DIRS for part in file.parts)
        ]
        base = root

    records: list[dict] = []
    parsed = 0
    parse_failures = 0
    for file in sorted(files):
        try:
            source = file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(file))
        except (OSError, UnicodeError):
            parse_failures += 1
            continue
        except SyntaxError:
            parse_failures += 1
            continue
        relative = file.relative_to(base).as_posix()
        visitor = _InventoryVisitor(relative, source.splitlines())
        visitor.visit(tree)
        records.extend(visitor.records)
        parsed += 1

    counts: dict[str, int] = {}
    for record in records:
        counts[record["classification"]] = counts.get(record["classification"], 0) + 1
    return {
        "schema_version": "1.0",
        "inventory_type": "static_python_crypto_api_observations",
        "scope_note": "Not whole-program analysis; dynamic calls, configuration, key sizes, non-Python code, and runtime-loaded crypto may be missed.",
        "root": str(path),
        "files_considered": len(files),
        "files_parsed": parsed,
        "files_parse_failed": parse_failures,
        "observation_count": len(records),
        "unique_algorithms": sorted({record["algorithm"] for record in records}),
        "by_classification": dict(sorted(counts.items())),
        "observations": sorted(records, key=lambda row: (row["file"], row["line"], row["algorithm"], row["api"])),
    }


def inventory_json(path: Path) -> str:
    return json.dumps(build_inventory(path), indent=2, sort_keys=True)
