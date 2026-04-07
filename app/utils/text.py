"""Text processing utilities."""

from __future__ import annotations


def truncate(text: str, max_len: int = 500) -> str:
    """Truncate text to a max length, adding ellipsis if needed."""
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


def safe_filename(name: str) -> str:
    """Sanitize a string for use as a filename."""
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
