"""Regression tests for source-tree traversal boundaries."""

from pathlib import Path

from pqcscanner.scanner import scan_path


def test_scan_path_skips_symlinked_files(tmp_path: Path):
    source_tree = tmp_path / "source"
    source_tree.mkdir()
    external = tmp_path / "external.py"
    external.write_text("import rsa\n", encoding="utf-8")
    link = source_tree / "linked.py"

    try:
        link.symlink_to(external)
    except (NotImplementedError, OSError) as exc:
        import pytest
        pytest.skip(f"symlinks are unavailable: {exc}")

    assert scan_path(source_tree) == []
    assert scan_path(link) == []


def test_scan_path_still_scans_regular_files(tmp_path: Path):
    source = tmp_path / "sample.py"
    source.write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n", encoding="utf-8")

    findings = scan_path(source)

    assert findings
    assert any("RSA" in finding.algorithm for finding in findings)


def test_scan_path_skips_unsupported_direct_file(tmp_path: Path):
    source = tmp_path / "notes.txt"
    source.write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n",
        encoding="utf-8",
    )

    assert scan_path(source) == []
