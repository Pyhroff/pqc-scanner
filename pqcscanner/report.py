"""Output formatters: text (Rich), JSON, HTML."""

import json
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


def to_sarif(findings: list[Finding], scanned_path: str = "") -> str:
    """Serialize findings as SARIF 2.1.0 for CI and downstream security tooling."""
    import hashlib

    def rule_id(f: Finding) -> str:
        algorithm = "".join(ch.lower() if ch.isalnum() else "-" for ch in f.algorithm).strip("-")
        bucket = f.bucket.value
        return f"pqc.{bucket}.{algorithm or 'unknown'}"

    rules_by_id: dict[str, dict] = {}
    results: list[dict] = []
    level_map = {
        Severity.CRITICAL: "error",
        Severity.WARNING: "warning",
        Severity.INFORMATIONAL: "note",
    }
    for finding in findings:
        rid = rule_id(finding)
        if rid not in rules_by_id:
            rules_by_id[rid] = {
                "id": rid,
                "name": finding.algorithm,
                "shortDescription": {"text": f"{finding.algorithm} finding ({finding.bucket.value})"},
                "defaultConfiguration": {"level": level_map.get(finding.severity, "note")},
                "properties": {"bucket": finding.bucket.value, "algorithm": finding.algorithm},
            }
        rule_index = list(rules_by_id).index(rid)
        uri = Path(finding.file).as_posix()
        location = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
        if isinstance(finding.line, int) and finding.line > 0:
            location["physicalLocation"]["region"] = {"startLine": finding.line}
        results.append({
            "ruleId": rid,
            "ruleIndex": rule_index,
            "level": level_map.get(finding.severity, "note"),
            "message": {"text": f"{finding.context} Recommendation: {finding.recommendation}"},
            "locations": [location],
            "properties": {
                "bucket": finding.bucket.value,
                "algorithm": finding.algorithm,
                "recommendation": finding.recommendation,
                "evidence_type": "static_source_code_finding",
            },
        })

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "pqc-scanner",
                "informationUri": "https://github.com/Pyhroff/pqc-scanner",
                "rules": list(rules_by_id.values()),
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
