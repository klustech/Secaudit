"""Backward-compatible re-export — all logic lives in sanitization_policy.py.

New code should import directly from ``app.services.sanitization_policy``.
This module exists so that existing imports continue to work without changes
outside the core codebase.
"""

from app.services.sanitization_policy import (  # noqa: F401 — re-exports
    contains_unsafe_terms,
    is_sanitized,
    sanitize_dict,
    sanitize_model,
    sanitize_text,
)
