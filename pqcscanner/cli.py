"""pqc-scan CLI — scan and ci commands."""

import sys
from pathlib import Path

import typer
from rich.console import Console

from pqcscanner.scanner import scan_path
from pqcscanner.taxonomy import Bucket, Severity
from pqcscanner.report import print_text_report, to_json, to_html, to_sarif

app = typer.Typer(
    help=(
        "Detect quantum-vulnerable cryptography and recommend NIST PQC replacements.\n\n"
        "Three severity buckets:\n"
        "  CRITICAL  — quantum-broken (Shor's algorithm, RSA/ECC/DH/DSA)\n"
        "  WARNING   — classically broken (MD5/SHA-1/DES/RC4) or Grover-weakened\n"
        "  INFO      — advisory"
    ),
    no_args_is_help=True,
)
_console = Console()

_SEV_ORDER = {"critical": 3, "warning": 2, "informational": 1}


@app.command()
def scan(
    path: Path = typer.Argument(..., help="File or directory to scan", exists=True),
    format: str = typer.Option("text", "--format", "-f", help="text | json | html | sarif"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write to file instead of stdout"),
    min_severity: str = typer.Option("warning", "--min-severity", help="Minimum severity to show: critical | warning | informational"),
) -> None:
    """Scan a codebase for quantum-vulnerable and classically-broken cryptography."""
    if format != "sarif" or output is not None:
        _console.print(f"[dim]Scanning {path} …[/]")
    findings = scan_path(path)

    threshold = _SEV_ORDER.get(min_severity.lower(), 2)
    findings = [f for f in findings if _SEV_ORDER.get(f.severity.value, 0) >= threshold]

    if format == "json":
        result = to_json(findings)
        if output:
            output.write_text(result, encoding="utf-8")
            _console.print(f"[green]JSON report → {output}[/]")
        else:
            print(result)
    elif format == "html":
        result = to_html(findings, scanned_path=str(path))
        out = output or Path("pqc-report.html")
        out.write_text(result, encoding="utf-8")
        _console.print(f"[green]HTML report → {out}[/]")
    else:
        print_text_report(findings, _console)

    raise typer.Exit(0)


@app.command()
def ci(
    path: Path = typer.Argument(..., help="File or directory to scan", exists=True),
    fail_on: str = typer.Option("critical", "--fail-on", help="Fail if findings at this severity or above: critical | warning"),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable JSON output"),
) -> None:
    """CI/CD gate — exits 1 if findings at --fail-on level are present.

    Exit codes: 0 = clean · 1 = findings found · 2 = error
    """
    findings = scan_path(path)

    threshold = _SEV_ORDER.get(fail_on.lower(), 3)
    failures = [f for f in findings if _SEV_ORDER.get(f.severity.value, 0) >= threshold]

    qb = sum(1 for f in failures if f.bucket == Bucket.QUANTUM_BROKEN)
    cb = sum(1 for f in failures if f.bucket == Bucket.CLASSICALLY_BROKEN)
    qw = sum(1 for f in failures if f.bucket == Bucket.QUANTUM_WEAKENED)
    passed = len(failures) == 0

    if json_out:
        import json
        print(json.dumps({
            "passed": passed,
            "fail_on": fail_on,
            "total_findings": len(failures),
            "quantum_broken": qb,
            "classically_broken": cb,
            "quantum_weakened": qw,
        }))
    else:
        if passed:
            _console.print(f"[bold green]✓ PASS[/] — no findings at [{fail_on}] severity")
        else:
            _console.print(f"[bold red]✗ FAIL[/] — {len(failures)} finding(s) at [{fail_on}] severity or above")
            print_text_report(failures, _console)

    raise typer.Exit(0 if passed else 1)
