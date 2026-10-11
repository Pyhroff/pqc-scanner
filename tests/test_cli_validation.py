"""CLI input validation regressions: invalid options must fail closed."""

from typer.testing import CliRunner

from pqcscanner.cli import app


runner = CliRunner()


def test_scan_rejects_unknown_format_before_scanning(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "sariff"])
    assert result.exit_code != 0
    assert "format must be one of" in result.output


def test_scan_rejects_unknown_severity_before_scanning(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path), "--min-severity", "urgent"])
    assert result.exit_code != 0
    assert "min-severity must be one of" in result.output


def test_ci_rejects_unknown_fail_on_before_scanning(tmp_path):
    result = runner.invoke(app, ["ci", str(tmp_path), "--fail-on", "informational"])
    assert result.exit_code != 0
    assert "fail-on must be one of" in result.output
