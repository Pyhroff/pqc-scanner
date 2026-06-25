"""File walker — dispatches each file to the appropriate detector."""

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
    """Walk root recursively and return all findings across all scanned files."""
    if root.is_file():
        return _scan_file(root)

    findings: list[Finding] = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and _should_scan(path):
            findings.extend(_scan_file(path))
    return findings


def _should_scan(path: Path) -> bool:
    for part in path.parts:
        if part in _SKIP_DIRS:
            return False
    suffix = path.suffix.lower()
    if suffix in _SKIP_EXTENSIONS:
        return False
    # Skip minified JS
    if path.name.endswith(".min.js") or path.name.endswith(".min.ts"):
        return False
    return suffix in _SCAN_EXTENSIONS or path.name in _SCAN_NAMES


def _scan_file(path: Path) -> list[Finding]:
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return []
    if path.suffix.lower() == ".py":
        return detect_python(path, source)
    return detect_generic(path, source)
