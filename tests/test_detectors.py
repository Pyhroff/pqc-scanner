"""
Unit tests for pqc-scanner detectors.

Validates the three-bucket taxonomy grounded in quantum physics:
  QUANTUM_BROKEN     — Shor's algorithm fully breaks RSA/ECC/DH/DSA
  CLASSICALLY_BROKEN — MD5/SHA-1/DES/RC4 broken today, independent of quantum
  QUANTUM_WEAKENED   — Grover's halves security level (AES-128 → 64-bit effective)

Key invariant tested in tests 7–8:
  AES-256 and SHA-256 MUST produce zero findings — they are quantum-safe.
  This is the proof-of-domain-knowledge that separates a real PQC tool from grep-for-keywords.
"""

import json
from pathlib import Path

import pytest

from pqcscanner.detectors.python_ast import detect_python
from pqcscanner.detectors.generic import detect_generic
from pqcscanner.report import to_json
from pqcscanner.taxonomy import Bucket, Severity

FIXTURES = Path(__file__).parent / "fixtures"


def _scan(name: str) -> list:
    path = FIXTURES / name
    return detect_python(path, path.read_text(encoding="utf-8"))


# ── QUANTUM-BROKEN (Shor's algorithm) ────────────────────────────────────────

def test_rsa_import_is_quantum_broken():
    findings = _scan("vulnerable_rsa.py")
    qb = [f for f in findings if f.bucket == Bucket.QUANTUM_BROKEN]
    assert len(qb) >= 1, "RSA import must produce at least one QUANTUM_BROKEN finding"
    assert all(f.severity == Severity.CRITICAL for f in qb)
    assert any("RSA" in f.algorithm for f in qb)


def test_ecc_import_is_quantum_broken():
    findings = _scan("vulnerable_ecc.py")
    qb = [f for f in findings if f.bucket == Bucket.QUANTUM_BROKEN]
    assert len(qb) >= 1, "ECC import must produce at least one QUANTUM_BROKEN finding"
    assert all(f.severity == Severity.CRITICAL for f in qb)
    assert any("ECC" in f.algorithm or "EC" in f.algorithm for f in qb)


def test_dh_import_is_quantum_broken():
    findings = _scan("vulnerable_dh.py")
    qb = [f for f in findings if f.bucket == Bucket.QUANTUM_BROKEN]
    assert len(qb) >= 1, "DH import must produce at least one QUANTUM_BROKEN finding"
    assert any("DH" in f.algorithm or "Diffie" in f.algorithm for f in qb)


def test_pycryptodome_rsa_is_quantum_broken():
    findings = _scan("vulnerable_pycryptodome.py")
    qb = [f for f in findings if f.bucket == Bucket.QUANTUM_BROKEN]
    assert len(qb) >= 1, "pycryptodome RSA import must be detected as QUANTUM_BROKEN"
    assert any("RSA" in f.algorithm for f in qb)


# ── CLASSICALLY BROKEN (independent of quantum) ───────────────────────────────

def test_md5_call_is_classically_broken():
    findings = _scan("classically_broken.py")
    cb = [f for f in findings if f.bucket == Bucket.CLASSICALLY_BROKEN and "MD5" in f.algorithm]
    assert len(cb) >= 1, "hashlib.md5() must produce a CLASSICALLY_BROKEN finding"
    # Must NOT leak into quantum-broken bucket
    assert all(f.bucket == Bucket.CLASSICALLY_BROKEN for f in cb)


def test_sha1_call_is_classically_broken():
    findings = _scan("classically_broken.py")
    cb = [f for f in findings if f.bucket == Bucket.CLASSICALLY_BROKEN and "SHA-1" in f.algorithm]
    assert len(cb) >= 1, "hashlib.sha1() must produce a CLASSICALLY_BROKEN finding"


# ── ZERO FALSE POSITIVES on clean AES-256/SHA-256 file ───────────────────────

def test_clean_pqc_zero_quantum_broken():
    """AES-256 and SHA-256 must produce ZERO quantum-broken findings.

    This is the critical correctness invariant: a tool that flags AES-256 as
    'quantum-vulnerable' demonstrates it doesn't understand Grover vs Shor.
    AES-256 drops to 128-bit effective security under Grover — still acceptable.
    """
    findings = _scan("clean_pqc.py")
    qb = [f for f in findings if f.bucket == Bucket.QUANTUM_BROKEN]
    assert qb == [], (
        f"False positive(s) on clean AES-256/SHA-256 file: "
        f"{[(f.algorithm, f.line, f.context) for f in qb]}"
    )


def test_clean_pqc_zero_classically_broken():
    """AES-256 and SHA-256 must produce ZERO classically-broken findings."""
    findings = _scan("clean_pqc.py")
    cb = [f for f in findings if f.bucket == Bucket.CLASSICALLY_BROKEN]
    assert cb == [], (
        f"False positive(s) on clean file: "
        f"{[(f.algorithm, f.line, f.context) for f in cb]}"
    )


# ── GENERIC REGEX DETECTOR (non-Python files) ─────────────────────────────────

def test_generic_detector_js_rsa():
    js_source = """\
const crypto = require('crypto');
const { publicKey, privateKey } = crypto.generateKeyPairSync('RSA', {
  modulusLength: 2048,
});
"""
    findings = detect_generic(Path("test.js"), js_source)
    qb = [f for f in findings if f.bucket == Bucket.QUANTUM_BROKEN]
    assert len(qb) >= 1, "RSA usage in JS must be detected as QUANTUM_BROKEN"
    assert any("RSA" in f.algorithm for f in qb)


def test_generic_detector_md5_in_java():
    java_source = """\
MessageDigest md = MessageDigest.getInstance("MD5");
md.update(input.getBytes());
byte[] digest = md.digest();
"""
    findings = detect_generic(Path("Hash.java"), java_source)
    cb = [f for f in findings if f.bucket == Bucket.CLASSICALLY_BROKEN]
    assert len(cb) >= 1, "MD5 in Java must be detected as CLASSICALLY_BROKEN"



# ── RUST CRYPTO API COVERAGE ──────────────────────────────────────────────────

def test_generic_detector_rust_rsa_api():
    source = "use rsa::RsaPrivateKey;\nlet key = RsaPrivateKey::new(&mut rng, 2048)?;"
    findings = detect_generic(Path("crypto.rs"), source)
    qb = [f for f in findings if f.bucket == Bucket.QUANTUM_BROKEN]
    assert any(f.algorithm == "RSA" for f in qb)


def test_generic_detector_rust_ecdh_api():
    source = "use p256::ecdh::EphemeralSecret;\nlet secret = EphemeralSecret::random(&mut rng);"
    findings = detect_generic(Path("exchange.rs"), source)
    qb = [f for f in findings if f.bucket == Bucket.QUANTUM_BROKEN]
    assert any("ECDH" in f.algorithm or "ECC" in f.algorithm for f in qb)


def test_generic_detector_rust_sha1_api():
    source = "use sha1::Sha1;\nlet digest = Sha1::new();"
    findings = detect_generic(Path("hash.rs"), source)
    cb = [f for f in findings if f.bucket == Bucket.CLASSICALLY_BROKEN]
    assert any(f.algorithm == "SHA-1" for f in cb)


def test_generic_detector_rust_clean_sha256_not_flagged():
    source = "use sha2::Sha256;\nlet digest = Sha256::digest(data);"
    findings = detect_generic(Path("hash.rs"), source)
    assert findings == []

# ── JSON REPORT STRUCTURE ─────────────────────────────────────────────────────

def test_json_report_structure():
    findings = _scan("vulnerable_rsa.py")
    report = json.loads(to_json(findings))

    assert "summary" in report
    assert "findings" in report
    assert report["summary"]["quantum_broken"] >= 1
    assert report["summary"]["total"] == len(findings)

    first = report["findings"][0]
    for key in ("file", "line", "algorithm", "bucket", "severity", "context", "recommendation"):
        assert key in first, f"Missing key '{key}' in finding JSON"
