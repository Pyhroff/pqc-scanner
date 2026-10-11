"""Deterministic, bounded file walker for the source detectors."""

import os
from pathlib import Path

from pqcscanner.detectors.python_ast import detect_python
from pqcscanner.detectors.generic import detect_generic
from pqcscanner.taxonomy import Finding

_SKIP_DIRS = frozenset({
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", "site-packages",
    ".next", "out", "coverage",
})

_SKIP_EXTENSIONS = frozenset({
    ".pyc", ".pyo", ".map", ".lock", ".sum", ".pdf",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".zip", ".tar", ".gz", ".bin", ".exe",
})

_SCAN_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx",
    ".java", ".kt", ".go", ".rb", ".php", ".cs", ".rs",
    ".conf", ".cfg", ".cnf", ".nginx", ".yml", ".yaml", ".json",
    ".sh", ".bash", ".zsh", ".fish",
})

_SCAN_NAMES = frozenset({"Dockerfile", "nginx.conf", ".env.example", ".env.sample"})


def scan_path(root: Path) -> list[Finding]:
    """Scan a file or tree, pruning excluded directories before traversal.

    Directory and file ordering is stable so repeated scans produce stable
    report ordering. Symlinks are deliberately not followed.
    """
    root = Path(root)
    if root.is_symlink():
        return []
    if root.is_file():
        return _scan_file(root) if _should_scan(root) else []
    if not root.is_dir():
        return []

    findings: list[Finding] = []
    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        # Prune rather than merely ignore: large dependency/build trees should
        # not be traversed at all.
        dirnames[:] = sorted(
            name for name in dirnames
            if name not in _SKIP_DIRS
            and not (current_path / name).is_symlink()
        )
        for name in sorted(filenames):
            path = current_path / name
            if path.is_symlink() or not _should_scan(path):
                continue
            findings.extend(_scan_file(path))
    return findings


def _should_scan(path: Path) -> bool:
    if any(part in _SKIP_DIRS for part in path.parts):
        return False
    suffix = path.suffix.lower()
    if suffix in _SKIP_EXTENSIONS:
        return False
    if path.name.endswith((".min.js", ".min.ts")):
        return False
    return suffix in _SCAN_EXTENSIONS or path.name in _SCAN_NAMES


def _scan_file(path: Path) -> list[Finding]:
    # Do not follow links to files outside the requested source tree.
    if path.is_symlink():
        return []
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        # Unreadable or concurrently removed files should not abort a scan.
        return []
    if path.suffix.lower() == ".py":
        return detect_python(path, source)
    return detect_generic(path, source)
