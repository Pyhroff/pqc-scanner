"""Validate a SARIF 2.1.0 document against the official OASIS JSON Schema."""
from __future__ import annotations

import argparse
import json
import sys
from urllib.request import Request, urlopen

from jsonschema import Draft4Validator

SCHEMA_URL = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/"
    "errata01/os/schemas/sarif-schema-2.1.0.json"
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", help="SARIF JSON report to validate")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--expect-findings", action="store_true")
    group.add_argument("--expect-empty", action="store_true")
    args = parser.parse_args()

    with open(args.report, encoding="utf-8") as handle:
        payload = json.load(handle)

    request = Request(SCHEMA_URL, headers={"User-Agent": "pqc-scanner-sarif-validator/1.0"})
    with urlopen(request, timeout=30) as response:
        schema = json.load(response)

    Draft4Validator.check_schema(schema)
    errors = sorted(
        Draft4Validator(schema).iter_errors(payload),
        key=lambda error: list(map(str, error.absolute_path)),
    )
    if errors:
        for error in errors:
            path = "$" + "".join(f"[{part!r}]" for part in error.absolute_path)
            print(f"{path}: {error.message}", file=sys.stderr)
        return 1

    results = [
        result
        for run in payload.get("runs", [])
        for result in run.get("results", [])
    ]
    if args.expect_findings and not results:
        print("Expected at least one SARIF finding, but results were empty.", file=sys.stderr)
        return 1
    if args.expect_empty and results:
        print(f"Expected no SARIF findings, got {len(results)}.", file=sys.stderr)
        return 1

    print(f"SARIF 2.1.0 schema valid: {args.report} ({len(results)} finding(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
