from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Bucket(str, Enum):
    """Which threat category the finding belongs to.

    The distinction matters: QUANTUM_BROKEN algorithms must be replaced before a
    cryptographically-relevant quantum computer (CRQC) arrives; CLASSICALLY_BROKEN
    ones should be replaced today regardless of quantum; QUANTUM_WEAKENED ones
    need a key-size check, not necessarily a full algorithm swap.
    """
    QUANTUM_BROKEN = "quantum_broken"          # Shor's: fully broken by a CRQC
    QUANTUM_WEAKENED = "quantum_weakened"      # Grover's: security level halved
    CLASSICALLY_BROKEN = "classically_broken"  # Already weak today, independent of quantum


class Severity(str, Enum):
    CRITICAL = "critical"           # Shor-vulnerable — must replace
    WARNING = "warning"             # Classically broken or Grover-weakened below safe margin
    INFORMATIONAL = "informational" # Advisory


# NIST PQC standards finalized August 2024
NIST_PQC = {
    "ML-KEM": "FIPS 203 — Module-Lattice Key Encapsulation (replaces RSA/DH/ECDH)",
    "ML-DSA": "FIPS 204 — Module-Lattice Digital Signature (replaces RSA-sign/ECDSA/DSA)",
    "SLH-DSA": "FIPS 205 — Stateless Hash-Based Digital Signature (conservative fallback)",
    "FN-DSA": "Draft FIPS 206 — FALCON, compact lattice signatures",
}

LIBOQS_PY = "https://github.com/open-quantum-safe/liboqs-python"


@dataclass
class Finding:
    file: Path
    line: int
    algorithm: str
    bucket: Bucket
    severity: Severity
    context: str        # source line snippet
    recommendation: str
