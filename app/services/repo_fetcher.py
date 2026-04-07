"""Download a public GitHub repo as a zip archive and extract it."""

from __future__ import annotations

import io
import re
import zipfile
from pathlib import Path

import httpx

from app.config import settings

_GITHUB_URL_RE = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$"
)


def parse_github_url(url: str) -> tuple[str, str]:
    """Return (owner, repo) from a GitHub URL or raise ValueError."""
    m = _GITHUB_URL_RE.match(url.strip())
    if not m:
        raise ValueError(f"Not a valid public GitHub repo URL: {url}")
    return m.group("owner"), m.group("repo")


async def fetch_repo(repo_url: str, ref: str = "main", dest: Path | None = None) -> Path:
    """Download and extract a GitHub repo archive.

    Returns the path to the extracted root directory.
    """
    owner, repo = parse_github_url(repo_url)
    archive_url = f"https://github.com/{owner}/{repo}/archive/{ref}.zip"

    async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
        resp = await client.get(archive_url)
        resp.raise_for_status()

    size_mb = len(resp.content) / (1024 * 1024)
    if size_mb > settings.max_repo_mb:
        raise ValueError(
            f"Repo archive is {size_mb:.1f} MB, exceeds limit of {settings.max_repo_mb} MB"
        )

    if dest is None:
        dest = settings.job_storage_path / "repos"
    dest.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        zf.extractall(dest)
        # GitHub zips contain a single root folder like repo-ref/
        top = {p.split("/")[0] for p in zf.namelist() if "/" in p}

    if len(top) == 1:
        return dest / top.pop()
    return dest
