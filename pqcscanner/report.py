"""Output formatters: text (Rich), JSON, HTML."""

import hashlib
import json
import re
from pathlib import Path

from rich import box
from rich.console import Console
from rich.table import Table

from pqcscanner.taxonomy import Bucket, Finding, Severity


def print_text_report(findings: list[Finding], console: Console | None = None) -> None:
    c = console or Console()

    if not findings:
        c.print("[bold green]✓ No quantum-vulnerable or classically-broken cryptography detected.[/]")
        return

    qb = [f for f in findings if f.bucket == Bucket.QUANTUM_BROKEN]
    cb = [f for f in findings if f.bucket == Bucket.CLASSICALLY_BROKEN]
    qw = [f for f in findings if f.bucket == Bucket.QUANTUM_WEAKENED]

    def _section(label: str, color: str, section_findings: list[Finding]) -> None:
        if not section_findings:
            return
        n = len(section_findings)
        c.print(f"\n[bold {color}]━━ {label} ({n} finding{'s' if n != 1 else ''}) ━━[/]")
        t = Table(box=box.SIMPLE, show_header=True, pad_edge=False, expand=False)
        t.add_column("File", style="cyan")
        t.add_column("Ln", style="dim", width=5)
        t.add_column("Algorithm", style="bold", width=22)
        t.add_column("Context", style="dim")
        t.add_column("Recommendation", style="green")
        for f in section_findings:
            ctx = f.context[:70] + ("…" if len(f.context) > 70 else "")
            rec = f.recommendation[:90] + ("…" if len(f.recommendation) > 90 else "")
            t.add_row(str(f.file), str(f.line), f.algorithm, ctx, rec)
        c.print(t)

    _section("QUANTUM-BROKEN  (Shor's — replace before a CRQC arrives)", "red", qb)
    _section("CLASSICALLY BROKEN  (weak today, independent of quantum)", "orange3", cb)
    _section("QUANTUM-WEAKENED  (Grover's — verify key lengths)", "yellow", qw)

    c.print(
        f"\n[bold]Summary:[/] {len(qb)} quantum-broken  ·  "
        f"{len(cb)} classically broken  ·  {len(qw)} quantum-weakened"
    )
    c.print("[dim]NIST PQC (Aug 2024): ML-KEM FIPS 203 · ML-DSA FIPS 204 · SLH-DSA FIPS 205[/]")


def to_json(findings: list[Finding]) -> str:
    qb = [f for f in findings if f.bucket == Bucket.QUANTUM_BROKEN]
    cb = [f for f in findings if f.bucket == Bucket.CLASSICALLY_BROKEN]
    qw = [f for f in findings if f.bucket == Bucket.QUANTUM_WEAKENED]
    return json.dumps(
        {
            "summary": {
                "total": len(findings),
                "quantum_broken": len(qb),
                "classically_broken": len(cb),
                "quantum_weakened": len(qw),
            },
            "findings": [
                {
                    "file": str(f.file),
                    "line": f.line,
                    "algorithm": f.algorithm,
                    "bucket": f.bucket.value,
                    "severity": f.severity.value,
                    "context": f.context,
                    "recommendation": f.recommendation,
                }
                for f in findings
            ],
        },
        indent=2,
    )


def to_html(findings: list[Finding], scanned_path: str = "") -> str:
    qb = [f for f in findings if f.bucket == Bucket.QUANTUM_BROKEN]
    cb = [f for f in findings if f.bucket == Bucket.CLASSICALLY_BROKEN]
    qw = [f for f in findings if f.bucket == Bucket.QUANTUM_WEAKENED]

    def _rows(bucket_findings: list[Finding]) -> str:
        return "".join(
            f"<tr>"
            f"<td><code>{f.file}</code></td>"
            f"<td style='color:#888'>{f.line}</td>"
            f"<td><strong>{f.algorithm}</strong></td>"
            f"<td><code style='font-size:.8em'>{f.context[:100]}</code></td>"
            f"<td style='color:#a0d8a0;font-size:.85em'>{f.recommendation}</td>"
            f"</tr>"
            for f in bucket_findings
        )

    def _section(title: str, color: str, bucket_findings: list[Finding]) -> str:
        if not bucket_findings:
            return ""
        return (
            f"<h2 style='color:{color};margin-top:2em'>{title} "
            f"<span style='font-weight:normal;font-size:.7em'>({len(bucket_findings)})</span></h2>"
            "<table><thead><tr>"
            "<th>File</th><th>Line</th><th>Algorithm</th><th>Context</th><th>Recommendation</th>"
            f"</tr></thead><tbody>{_rows(bucket_findings)}</tbody></table>"
        )

    body = (
        _section("⚠ Quantum-Broken (Shor's algorithm — critical priority)", "#ff6b6b", qb)
        + _section("✗ Classically Broken (weak today, independent of quantum)", "#ff9f43", cb)
        + _section("~ Quantum-Weakened (Grover's — verify key lengths)", "#ffd93d", qw)
    ) or '<p style="color:#51cf66;font-size:1.2em">✓ No quantum-vulnerable cryptography detected.</p>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PQC Scanner Report</title>
<style>
body{{background:#0d1117;color:#e6edf3;font-family:'Segoe UI',system-ui,sans-serif;max-width:1200px;margin:0 auto;padding:2em}}
h1{{color:#79c0ff}}h2{{border-bottom:1px solid #30363d;padding-bottom:.3em}}
table{{width:100%;border-collapse:collapse;margin-top:1em;font-size:.9em}}
th{{background:#161b22;color:#8b949e;text-align:left;padding:8px 12px;border-bottom:1px solid #30363d}}
td{{padding:8px 12px;border-bottom:1px solid #21262d;vertical-align:top}}
code{{background:#161b22;padding:2px 6px;border-radius:4px}}
.summary{{display:flex;gap:2em;margin:1.5em 0}}
.stat{{background:#161b22;border-radius:8px;padding:1em 1.5em;text-align:center}}
.stat .num{{font-size:2em;font-weight:bold}}
.footer{{margin-top:3em;color:#8b949e;font-size:.85em;border-top:1px solid #30363d;padding-top:1em}}
a{{color:#79c0ff}}
</style>
</head>
<body>
<h1>PQC Scanner Report</h1>
<p>Scanned: <code>{scanned_path}</code></p>
<div class="summary">
  <div class="stat"><div class="num" style="color:#ff6b6b">{len(qb)}</div><div>Quantum-Broken</div></div>
  <div class="stat"><div class="num" style="color:#ff9f43">{len(cb)}</div><div>Classically Broken</div></div>
  <div class="stat"><div class="num" style="color:#ffd93d">{len(qw)}</div><div>Quantum-Weakened</div></div>
  <div class="stat"><div class="num" style="color:#51cf66">{len(findings)}</div><div>Total</div></div>
</div>
{body}
<div class="footer">
  <strong>NIST PQC Standards (finalized August 2024):</strong>
  ML-KEM (FIPS 203) · ML-DSA (FIPS 204) · SLH-DSA (FIPS 205) · FN-DSA (Draft FIPS 206)<br>
  Reference implementation: <a href="https://github.com/open-quantum-safe/liboqs-python">liboqs-python</a>
</div>
</body>
</html>"""




def to_sarif(
    findings: list[Finding],
    tool_name: str = "pqc-scanner",
    scanned_path: str = "",
) -> str:
    """Serialize findings as SARIF 2.1.0 with stable IDs and bridge metadata."""
    rules: dict[str, dict] = {}
    results: list[dict] = []
    severity_map = {
        Severity.CRITICAL: ("error", "9.5"),
        Severity.WARNING: ("warning", "6.5"),
        Severity.INFORMATIONAL: ("note", "3.0"),
    }

    for finding in findings:
        slug = re.sub(r"[^a-z0-9]+", "-", finding.algorithm.lower()).strip("-") or "crypto"
        rule_id = f"pqc.{finding.bucket.value}.{slug}"
        level, security_severity = severity_map.get(finding.severity, ("note", "3.0"))
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": slug.replace("-", " ").title(),
            "shortDescription": {
                "text": f"{finding.bucket.value.replace('_', ' ').title()}: {finding.algorithm}"
            },
            "fullDescription": {"text": finding.recommendation},
            "help": {"text": finding.recommendation, "markdown": finding.recommendation},
            "defaultConfiguration": {"level": level},
            "properties": {
                "tags": ["security", "cryptography", "post-quantum"],
                "precision": "medium",
                "security-severity": security_severity,
                "bucket": finding.bucket.value,
                "algorithm": finding.algorithm,
            },
        })
        file_uri = Path(finding.file).as_posix()
        fingerprint_source = f"{file_uri}\n{finding.line}\n{rule_id}\n{finding.context}"
        result = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f"{finding.algorithm}: {finding.recommendation}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file_uri},
                    "region": {"startLine": max(1, int(finding.line))},
                }
            }],
            "partialFingerprints": {
                "primaryLocationLineHash": hashlib.sha256(
                    fingerprint_source.encode("utf-8")
                ).hexdigest()
            },
            "properties": {
                "bucket": finding.bucket.value,
                "algorithm": finding.algorithm,
                "context": finding.context,
                "recommendation": finding.recommendation,
                "evidence_type": "static_source_code_finding",
            },
        }
        results.append(result)

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": tool_name,
                "informationUri": "https://github.com/Pyhroff/pqc-scanner",
                "rules": [rules[k] for k in sorted(rules)],
            }},
            "results": results,
            "properties": {
                "scanned_path": scanned_path,
                "finding_count": len(results),
                "finding_set_sha256": hashlib.sha256(
                    json.dumps(results, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest(),
            },
        }],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
