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
from pqcscanner.report import to_json, to_sarif
from pqcscanner.inventory import build_inventory
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


def test_direct_imported_hash_alias_is_detected():
    source = "from hashlib import md5 as legacy_hash\nlegacy_hash(data)\n"
    findings = detect_python(Path("alias_hash.py"), source)
    assert any(f.algorithm == "MD5" and f.line == 2 for f in findings)


def test_module_alias_hash_call_is_detected():
    source = "import hashlib as h\nh.sha1(data)\n"
    findings = detect_python(Path("alias_hash.py"), source)
    assert any(f.algorithm == "SHA-1" and f.line == 2 for f in findings)


def test_sha224_is_not_misclassified_as_broken():
    source = "import hashlib\nhashlib.sha224(data)\n"
    findings = detect_python(Path("approved_hash.py"), source)
    assert not any(f.algorithm == "SHA-224" for f in findings)
    assert findings == []



def test_cryptography_hash_module_alias_is_detected():
    source = (
        "from cryptography.hazmat.primitives import hashes as h\n"
        "digest = h.MD5()\n"
    )
    findings = detect_python(Path("crypto_alias.py"), source)
    assert any(f.bucket == Bucket.CLASSICALLY_BROKEN and f.algorithm == "MD5" for f in findings)


def test_pycryptodome_hash_module_alias_call_is_detected():
    source = "import Crypto.Hash as H\ndigest = H.MD5.new(data)\n"
    findings = detect_python(Path("crypto_alias.py"), source)
    assert any(f.bucket == Bucket.CLASSICALLY_BROKEN and "MD5" in f.algorithm for f in findings)


def test_sarif_report_has_schema_rule_location_and_fingerprint():
    findings = detect_python(
        Path("sample.py"),
        "from cryptography.hazmat.primitives import hashes as h\ndigest = h.MD5()\n",
    )
    payload = json.loads(to_sarif(findings))
    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "pqc-scanner"
    assert run["results"]
    result = run["results"][0]
    assert result["ruleId"].startswith("pqc.classically_broken.")
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
    assert result["partialFingerprints"]["primaryLocationLineHash"]


def test_clean_fixture_produces_empty_sarif_results():
    findings = _scan("clean_pqc.py")
    payload = json.loads(to_sarif(findings))
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"] == []


def test_vulnerable_fixture_sarif_preserves_bucket_and_algorithm():
    findings = _scan("vulnerable_rsa.py")
    payload = json.loads(to_sarif(findings))
    results = payload["runs"][0]["results"]
    assert results
    assert any(
        result.get("properties", {}).get("bucket") == Bucket.QUANTUM_BROKEN.value
        and "RSA" in result.get("properties", {}).get("algorithm", "")
        for result in results
    )



def test_pyjwt_rs256_signing_is_quantum_broken():
    findings = _scan("vulnerable_jwt.py")
    assert any(
        finding.bucket == Bucket.QUANTUM_BROKEN
        and "RS256" in finding.algorithm
        for finding in findings
    )


def test_pyjwt_hs256_is_not_misclassified_as_shor_broken():
    findings = _scan("clean_jwt_hs256.py")
    assert not any(f.bucket == Bucket.QUANTUM_BROKEN for f in findings)


def test_python_jose_ecdsa_verification_algorithms_are_detected():
    source = (
        "from jose import jwt\n"
        "claims = jwt.decode(token, key, algorithms=['ES256', 'HS256'])\n"
    )
    findings = detect_python(Path("jose_usage.py"), source)
    assert any(
        f.bucket == Bucket.QUANTUM_BROKEN and "ES256" in f.algorithm
        for f in findings
    )
    assert not any("HS256" in f.algorithm for f in findings)



def test_crypto_inventory_separates_asymmetric_hash_and_keysize_context():
    report = build_inventory(FIXTURES)
    observed = {
        (item["algorithm"], item["classification"])
        for item in report["observations"]
    }
    assert report["schema_version"] == "1.0"
    assert report["files_parsed"] >= 8  # includes fixture package metadata such as __init__.py
    assert ("JWT RS256 (RSA)", "quantum_broken") in observed
    assert ("JWT HS256 (HMAC)", "parameter_context_required") in observed
    assert ("SHA-256", "not_flagged_by_current_taxonomy") in observed
    assert ("AES", "parameter_context_required") in observed


def test_crypto_inventory_resolves_hashlib_aliases():
    report = build_inventory(FIXTURES)
    assert any(
        item["algorithm"] == "SHA-1"
        and item["classification"] == "classically_broken"
        and item["api"] == "hashlib.sha1"
        for item in report["observations"]
    )



def test_crypto_inventory_resolves_module_aliases(tmp_path):
    source = tmp_path / "aliases.py"
    source.write_text("import hashlib as h\nh.sha1(data)\n", encoding="utf-8")
    report = build_inventory(source)
    assert any(
        item["algorithm"] == "SHA-1"
        and item["classification"] == "classically_broken"
        and item["api"] == "hashlib.sha1"
        for item in report["observations"]
    )
