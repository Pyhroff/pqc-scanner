# pqc-scanner

**Static analysis tool that detects quantum-vulnerable cryptography and recommends NIST PQC replacements.**

```bash
pqc-scan scan ./my-service            # find all vulnerable crypto
pqc-scan scan ./my-service -f html    # generate HTML report
pqc-scan ci ./my-service              # CI gate — exits 1 on critical findings
```

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square)
![Tests](https://img.shields.io/badge/tests-11%20passed-brightgreen?style=flat-square)
![NIST](https://img.shields.io/badge/NIST%20PQC-FIPS%20203%2F204%2F205-orange?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

> **Part of the Quantum arc:**
> [Quantum Collapse](https://github.com/Pyhroff/quantum-collapse) (what breaks when RSA dies) →
> [Quantum OS](https://github.com/Pyhroff/qec-lab) (the machine that breaks it) →
> **pqc-scanner** (how to survive it)

---

## Why three buckets, not one

Most "quantum-safe" scanners flag everything cryptographic. That's wrong — and an expert reviewing your codebase will know it immediately. The threat model splits along physical lines:

| Bucket | Physics | Examples | Priority |
|--------|---------|----------|----------|
| **QUANTUM-BROKEN** | Shor's algorithm — polynomial-time break | RSA, ECDSA, ECDH, DH, DSA | Replace before a CRQC arrives |
| **CLASSICALLY BROKEN** | Already weak today, no quantum needed | MD5, SHA-1, DES, 3DES, RC4 | Replace now |
| **QUANTUM-WEAKENED** | Grover's algorithm — quadratic speedup, halves security level | AES-128 → 64-bit effective | Check key size, usually just upgrade to 256-bit |

**AES-256 and SHA-256 are NOT flagged.** Grover's algorithm halves their security level (256 → 128 bits effective), which remains acceptable under current NIST guidance. A scanner that flags AES-256 as "quantum-vulnerable" has confused Shor and Grover.

---

## NIST PQC Standards (finalized August 2024)

| Standard | Algorithm | Replaces |
|----------|-----------|---------|
| **FIPS 203** | ML-KEM (Kyber) | RSA / ECDH / DH — key encapsulation |
| **FIPS 204** | ML-DSA (Dilithium) | RSA-sign / ECDSA / DSA — digital signatures |
| **FIPS 205** | SLH-DSA (SPHINCS+) | Hash-based conservative fallback |
| Draft FIPS 206 | FN-DSA (FALCON) | Compact lattice signatures |

Reference implementation: [liboqs-python](https://github.com/open-quantum-safe/liboqs-python)

---

## Quickstart

```bash
git clone https://github.com/Pyhroff/pqc-scanner
cd pqc-scanner
pip install -e .

# scan a directory
pqc-scan scan ./my-project

# HTML report
pqc-scan scan ./my-project --format html --output report.html

# CI/CD gate (exits 1 if critical findings)
pqc-scan ci ./my-project --fail-on critical --json
```

---

## CLI Reference

### `scan`

```
pqc-scan scan PATH [OPTIONS]

  --format        -f   text | json | html         [default: text]
  --output        -o   Write to file               [default: stdout]
  --min-severity       critical | warning | informational  [default: warning]
```

### `ci`

```
pqc-scan ci PATH [OPTIONS]

  --fail-on    critical | warning   [default: critical]
  --json       Machine-readable output

Exit codes:  0 = clean  ·  1 = findings at --fail-on level  ·  2 = error
```

---

## What gets detected

### Python (AST-based — zero false positives on import aliases or renamed modules)

| Library | Detected patterns |
|---------|------------------|
| `cryptography` | `from ...asymmetric import rsa/ec/dh/dsa/ed25519/x25519` |
| `pycryptodome` | `from Crypto.PublicKey import RSA/ECC/DSA/ElGamal` |
| `hashlib` | `hashlib.md5()`, `hashlib.sha1()`, `hashlib.new("md5", ...)` |
| `pycryptodome` | `from Crypto.Hash import MD5/SHA1`, `from Crypto.Cipher import DES/DES3/ARC4` |

### Non-Python (regex — JS, TS, Java, Kotlin, Go, config files)

RSA, ECDSA/ECDH, MD5, SHA-1, TLS 1.0/1.1, RC4, DES/3DES in `.js .ts .java .kt .go .conf .cfg .yml .yaml`

---

## Project Structure

```
pqc-scanner/
├── pqcscanner/
│   ├── taxonomy.py          # Bucket + Severity enums, Finding dataclass
│   ├── scanner.py           # File walker, dispatches by extension
│   ├── cli.py               # Typer CLI (scan, ci)
│   ├── report.py            # text (Rich) · JSON · HTML output
│   └── detectors/
│       ├── python_ast.py    # AST-based Python detector
│       ├── generic.py       # Regex detector for non-Python files
│       └── rules.yaml       # Detection rules (JS, Java, Go, config)
└── tests/
    ├── test_detectors.py    # 11 tests
    └── fixtures/
        ├── vulnerable_rsa.py
        ├── vulnerable_ecc.py
        ├── vulnerable_dh.py
        ├── vulnerable_pycryptodome.py
        ├── classically_broken.py
        └── clean_pqc.py     # AES-256 + SHA-256: MUST produce zero findings
```

---

## Example output

```
Scanning ./my-service …

━━ QUANTUM-BROKEN (Shor's algorithm — replace before a CRQC arrives) (3 findings) ━━
 File                    Ln  Algorithm       Context
 auth/jwt.py             12  RSA             from cryptography.hazmat.primitives.asymmetric import rsa
 tls/handshake.py         8  ECC/ECDSA/ECDH  from cryptography.hazmat.primitives.asymmetric import ec
 crypto/keys.py          34  RSA (pycrypt.)  from Crypto.PublicKey import RSA

━━ CLASSICALLY BROKEN (weak today, independent of quantum) (2 findings) ━━
 File                    Ln  Algorithm  Context
 utils/hash.py           21  MD5        return hashlib.md5(data).hexdigest()
 legacy/checksum.py       7  SHA-1      hashlib.sha1(content).hexdigest()

Summary: 3 quantum-broken · 2 classically broken · 0 quantum-weakened
NIST PQC (Aug 2024): ML-KEM FIPS 203 · ML-DSA FIPS 204 · SLH-DSA FIPS 205
```

---

## References

- NIST IR 8413: *Status Report on the Third Round of the NIST PQC Standardization Process* (2022)
- FIPS 203, 204, 205 — *NIST Post-Quantum Cryptography Standards* (August 2024)
- Mosca, M. *Cybersecurity in an era with quantum computers: will we be ready?* (2018)
- Gidney & Ekerå. *How to factor 2048-bit RSA integers in 8 hours using 20 million noisy qubits.* Quantum (2021)

---

## License

MIT — see [LICENSE](LICENSE).
