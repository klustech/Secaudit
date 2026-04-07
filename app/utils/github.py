"""GitHub URL utilities."""

from __future__ import annotations

import re

_GITHUB_URL_RE = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$"
)


def is_valid_github_url(url: str) -> bool:
    """Check if a URL is a valid public GitHub repo URL."""
    return bool(_GITHUB_URL_RE.match(url.strip()))


def extract_owner_repo(url: str) -> tuple[str, str] | None:
    """Extract (owner, repo) from a GitHub URL."""
    m = _GITHUB_URL_RE.match(url.strip())
    if m:
        return m.group("owner"), m.group("repo")
    return None
