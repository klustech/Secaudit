"""Hashing utilities for job IDs and deduplication."""

from __future__ import annotations

import hashlib
import uuid


def generate_job_id() -> str:
    """Generate a short unique job ID."""
    return uuid.uuid4().hex[:12]


def hash_content(content: str) -> str:
    """SHA-256 hash of string content."""
    return hashlib.sha256(content.encode()).hexdigest()
