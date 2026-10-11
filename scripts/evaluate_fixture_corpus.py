"""Evaluate the curated detector fixture corpus at fixture-level granularity.

This is a regression benchmark for a small, hand-labelled test corpus. Its
metrics are not estimates of production precision/recall.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pqcscanner.detectors.python_ast import detect_python
from pqcscanner.taxonomy import Bucket

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
EXPECTED = {
    "clean_pqc.py": set(),
    "clean_jwt_hs256.py": set(),
    "classically_broken.py": {Bucket.CLASSICALLY_BROKEN.value},
    "vulnerable_dh.py": {Bucket.QUANTUM_BROKEN.value},
    "vulnerable_ecc.py": {Bucket.QUANTUM_BROKEN.value},
    "vulnerable_pycryptodome.py": {Bucket.QUANTUM_BROKEN.value},
    "vulnerable_rsa.py": {Bucket.QUANTUM_BROKEN.value},
    "vulnerable_jwt.py": {Bucket.QUANTUM_BROKEN.value},
}
BUCKETS = [bucket.value for bucket in Bucket]


def score(tp: int, fp: int, fn: int, tn: int) -> dict:
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else 0.0 if precision is not None and recall is not None else None
    )
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1,
        "unit": "fixture_bucket_presence",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Write JSON report to this path")
    args = parser.parse_args()

    records = []
    confusion = {bucket: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for bucket in BUCKETS}
    failures = []
    for filename, expected in EXPECTED.items():
        path = FIXTURES / filename
        findings = detect_python(path, path.read_text(encoding="utf-8"))
        predicted = {finding.bucket.value for finding in findings}
        records.append({
            "fixture": filename,
            "expected_buckets": sorted(expected),
            "predicted_buckets": sorted(predicted),
            "finding_count": len(findings),
            "match": predicted == expected,
        })
        if predicted != expected:
            failures.append(filename)
        for bucket in BUCKETS:
            actual_positive = bucket in expected
            predicted_positive = bucket in predicted
            key = (
                "tp" if actual_positive and predicted_positive else
                "fn" if actual_positive else
                "fp" if predicted_positive else
                "tn"
            )
            confusion[bucket][key] += 1

    report = {
        "schema_version": "1.0",
        "benchmark": "pqc-scanner-curated-fixture-corpus",
        "measurement_unit": "fixture_bucket_presence",
        "interpretation": (
            "Small curated regression corpus; not a production precision/recall estimate."
        ),
        "fixture_count": len(records),
        "all_expected_labels_match": not failures,
        "per_bucket": {
            bucket: score(**counts) for bucket, counts in confusion.items()
        },
        "fixtures": records,
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if failures:
        print(f"Fixture labels diverged: {', '.join(failures)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
