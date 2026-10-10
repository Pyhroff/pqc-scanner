"""Regex-based detector for non-Python source files.

Uses rules.yaml to match patterns against file content line-by-line.
Applied to JS, TS, Java, Go, config files, etc.
"""

import re
from pathlib import Path

import yaml

from pqcscanner.taxonomy import Bucket, Finding, Severity

_RULES_FILE = Path(__file__).parent / "rules.yaml"
_RULES: dict | None = None


def _load_rules() -> dict:
    global _RULES
    if _RULES is None:
        _RULES = yaml.safe_load(_RULES_FILE.read_text(encoding="utf-8"))
    return _RULES


def detect_generic(path: Path, source: str) -> list[Finding]:
    """Match regex rules against a non-Python source file."""
    rules = _load_rules()
    suffix = path.suffix.lower()
    lines = source.splitlines()
    findings: list[Finding] = []

    bucket_map = {
        "quantum_broken": (Bucket.QUANTUM_BROKEN, Severity.CRITICAL),
        "classically_broken": (Bucket.CLASSICALLY_BROKEN, Severity.WARNING),
        "quantum_weakened": (Bucket.QUANTUM_WEAKENED, Severity.INFORMATIONAL),
    }

    for bucket_key, rule_list in rules.items():
        if bucket_key not in bucket_map:
            expected = ", ".join(sorted(bucket_map))
            raise ValueError(
                f"Unknown detector bucket {bucket_key!r}; expected one of: {expected}"
            )
        bucket, severity = bucket_map[bucket_key]

        for rule in rule_list:
            exts: list[str] = rule.get("extensions", [])
            if exts and suffix not in exts:
                continue

            try:
                pattern = re.compile(rule["pattern"])
            except (KeyError, re.error) as exc:
                raise ValueError(
                    f"Invalid regex rule in bucket {bucket_key!r} for "
                    f"{rule.get('algorithm', '<unknown algorithm>')!r}: {exc}"
                ) from exc
            seen_lines: set[int] = set()

            for lineno, line in enumerate(lines, start=1):
                if lineno in seen_lines:
                    continue
                if pattern.search(line):
                    seen_lines.add(lineno)
                    findings.append(Finding(
                        file=path,
                        line=lineno,
                        algorithm=rule["algorithm"],
                        bucket=bucket,
                        severity=severity,
                        context=line.strip(),
                        recommendation=rule["recommendation"].strip(),
                    ))

    return findings
