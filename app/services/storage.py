"""Simple JSON file storage for job state."""

from __future__ import annotations

import json
from pathlib import Path

from app.config import settings
from app.models.repo_analysis import RepoAnalysis


def _job_path(job_id: str) -> Path:
    return settings.job_storage_path / f"{job_id}.json"


def save_job(analysis: RepoAnalysis) -> None:
    """Persist analysis state to a JSON file."""
    settings.job_storage_path.mkdir(parents=True, exist_ok=True)
    path = _job_path(analysis.job_id)
    path.write_text(analysis.model_dump_json(indent=2))


def load_job(job_id: str) -> RepoAnalysis | None:
    """Load a job from disk, or return None if not found."""
    path = _job_path(job_id)
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    return RepoAnalysis(**data)


def list_jobs() -> list[str]:
    """List all job IDs."""
    settings.job_storage_path.mkdir(parents=True, exist_ok=True)
    return [p.stem for p in settings.job_storage_path.glob("*.json")]
