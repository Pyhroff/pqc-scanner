"""Configuration validation tests for generic crypto detection rules."""

import pytest

from pqcscanner import taxonomy
from pqcscanner.detectors import generic


def test_unknown_bucket_is_rejected_instead_of_misclassified(monkeypatch, tmp_path):
    monkeypatch.setattr(
        generic,
        "_RULES",
        {
            "quantum_brokne": [
                {
                    "algorithm": "RSA",
                    "pattern": r"\bRSA\b",
                    "recommendation": "Use a post-quantum alternative.",
                }
            ]
        },
    )

    with pytest.raises(ValueError, match="Unknown detector bucket"):
        generic.detect_generic(tmp_path / "sample.js", "const algorithm = 'RSA';")


def test_known_bucket_keeps_its_expected_classification(monkeypatch, tmp_path):
    monkeypatch.setattr(
        generic,
        "_RULES",
        {
            "quantum_broken": [
                {
                    "algorithm": "RSA",
                    "pattern": r"\bRSA\b",
                    "recommendation": "Use a post-quantum alternative.",
                }
            ]
        },
    )

    findings = generic.detect_generic(tmp_path / "sample.js", "const algorithm = 'RSA';")

    assert len(findings) == 1
    assert findings[0].bucket == taxonomy.Bucket.QUANTUM_BROKEN
    assert findings[0].severity == taxonomy.Severity.CRITICAL
