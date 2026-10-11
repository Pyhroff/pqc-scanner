"""Regression tests for source-tree traversal boundaries."""

from pathlib import Path

from pqcscanner.scanner import scan_path


RSA_SOURCE = "from cryptography.hazmat.primitives.asymmetric import rsa\n"


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
    source.write_text(RSA_SOURCE, encoding="utf-8")

    findings = scan_path(source)

    assert findings
    assert any("RSA" in finding.algorithm for finding in findings)


def test_scan_path_skips_unsupported_direct_file(tmp_path: Path):
    source = tmp_path / "notes.txt"
    source.write_text(RSA_SOURCE, encoding="utf-8")
    assert scan_path(source) == []


def test_scan_tree_prunes_dependency_directories(tmp_path: Path):
    app = tmp_path / "app.py"
    app.write_text(RSA_SOURCE, encoding="utf-8")
    dependency = tmp_path / "node_modules" / "vendor.py"
    dependency.parent.mkdir()
    dependency.write_text(RSA_SOURCE, encoding="utf-8")

    findings = scan_path(tmp_path)

    assert any(finding.file == app for finding in findings)
    assert all("node_modules" not in finding.file.parts for finding in findings)


def test_scan_order_is_deterministic(tmp_path: Path):
    (tmp_path / "z.py").write_text(RSA_SOURCE, encoding="utf-8")
    (tmp_path / "a.py").write_text(RSA_SOURCE, encoding="utf-8")

    first = scan_path(tmp_path)
    second = scan_path(tmp_path)

    assert [(str(f.file), f.line, f.algorithm) for f in first] == [
        (str(f.file), f.line, f.algorithm) for f in second
    ]


def test_missing_path_returns_no_findings(tmp_path: Path):
    assert scan_path(tmp_path / "does-not-exist") == []
