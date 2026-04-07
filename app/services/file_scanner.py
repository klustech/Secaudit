"""Scan an extracted repo directory for relevant files."""

from __future__ import annotations

from pathlib import Path

IGNORE_DIRS = {
    "node_modules", "lib", "artifacts", "cache", "out", "dist",
    ".git", ".github", "build", "coverage", "typechain", "typechain-types",
}

SOLIDITY_EXTS = {".sol"}
DOC_EXTS = {".md", ".txt", ".rst"}
CONFIG_EXTS = {".json", ".toml", ".yaml", ".yml"}


def scan_files(root: Path) -> dict[str, list[Path]]:
    """Walk the repo tree and return categorized file lists.

    Returns dict with keys: solidity, docs, configs, other
    """
    result: dict[str, list[Path]] = {
        "solidity": [],
        "docs": [],
        "configs": [],
        "other": [],
    }

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue

        # Skip ignored directories
        parts = path.relative_to(root).parts
        if any(p in IGNORE_DIRS for p in parts):
            continue

        ext = path.suffix.lower()
        if ext in SOLIDITY_EXTS:
            result["solidity"].append(path)
        elif ext in DOC_EXTS:
            result["docs"].append(path)
        elif ext in CONFIG_EXTS:
            result["configs"].append(path)
        else:
            result["other"].append(path)

    return result


def detect_language_mix(root: Path) -> dict[str, int]:
    """Count files by extension, ignoring vendor dirs."""
    counts: dict[str, int] = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        parts = path.relative_to(root).parts
        if any(p in IGNORE_DIRS for p in parts):
            continue
        ext = path.suffix.lower() or "(no ext)"
        counts[ext] = counts.get(ext, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: -x[1]))
