"""Canonical sanitization policy — single source of truth for output sanitization.

Architecture
------------
Sanitization is applied in layers (defense-in-depth):

1. **LLM service** (llm_service.py)
   Sanitizes raw LLM outputs immediately after generation.
   Role: first line of defense against model-generated exploit language.

2. **Pipeline** (routes_analyze.py)  [SOURCE OF TRUTH]
   Sanitizes all structured analysis results before persistence.
   This is the *authoritative* sanitization pass — data stored in the job
   store is guaranteed to be sanitized.

3. **API layer** (routes_jobs.py, routes_reports.py)  [DEFENSE-IN-DEPTH]
   Re-sanitizes on the way out as a safety net.  Because the pipeline
   already sanitized before storage, this pass is a no-op under normal
   conditions.  It exists to guard against:
   - future code paths that bypass the pipeline
   - manual edits to stored data

4. **Frontend** (gradio_app.py)
   Does NOT apply sanitization.  The API already guarantees sanitized
   responses; duplicating the work on the client adds latency with no
   safety benefit.

Idempotency guarantee
---------------------
``sanitize_text`` (and by extension every higher-level helper) is
**idempotent**: applying it twice yields the same result as applying it
once.  This is ensured by design — no replacement string contains a
substring that matches any unsafe pattern — and verified by tests.
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Pattern table — the single canonical list of unsafe → safe rewrites
# ---------------------------------------------------------------------------

_UNSAFE_PATTERNS: list[tuple[re.Pattern, str]] = [
    # More specific patterns MUST come before more general ones so the first
    # match wins (e.g. "exploit chain" before bare "exploit").
    (re.compile(r"\bexploit chain\b", re.IGNORECASE), "requires review"),
    (re.compile(r"\bexploit flow\b", re.IGNORECASE), "requires review"),
    (re.compile(r"\bexploit code\b", re.IGNORECASE), "requires review"),
    (re.compile(r"\bexploit\b", re.IGNORECASE), "requires review"),
    (re.compile(r"\bdrain path\b", re.IGNORECASE), "requires review"),
    (re.compile(r"\bbypass steps?\b", re.IGNORECASE), "should be validated"),
    (re.compile(r"\battacker can do .+? by\b", re.IGNORECASE), "manual confirmation needed"),
    (re.compile(r"\bproof of concept\b", re.IGNORECASE), "manual confirmation needed"),
    (re.compile(r"\bpayload\b", re.IGNORECASE), "should be validated"),
    (re.compile(r"\bweaponize\b", re.IGNORECASE), "requires review"),
    (re.compile(r"\battacker could drain\b", re.IGNORECASE), "may affect accounting/safety"),
    (re.compile(r"\battacker could\b", re.IGNORECASE), "may affect authorization/accounting/safety"),
    (re.compile(r"\battacker can\b", re.IGNORECASE), "may affect authorization/accounting/safety"),
    (re.compile(r"\bPoC\b"), "manual confirmation needed"),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def sanitize_text(text: str) -> str:
    """Replace unsafe exploit-oriented terms with safe review-oriented alternatives.

    This function is **idempotent** — calling it on already-sanitized text
    returns the same string unchanged.
    """
    for pattern, replacement in _UNSAFE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def contains_unsafe_terms(text: str) -> bool:
    """Return ``True`` if *text* contains any term that would be rewritten."""
    return any(pattern.search(text) for pattern, _ in _UNSAFE_PATTERNS)


def is_sanitized(text: str) -> bool:
    """Return ``True`` if *text* contains no unsafe terms (i.e. already clean)."""
    return not contains_unsafe_terms(text)


def sanitize_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively sanitize all string values in a dictionary.

    Returns a new dict — the original is never mutated.
    """
    sanitized: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, str):
            sanitized[key] = sanitize_text(value)
        elif isinstance(value, dict):
            sanitized[key] = sanitize_dict(value)
        elif isinstance(value, list):
            sanitized[key] = _sanitize_list(value)
        else:
            sanitized[key] = value
    return sanitized


def _sanitize_list(items: list) -> list:
    """Recursively sanitize all items in a list."""
    return [
        sanitize_text(item) if isinstance(item, str)
        else sanitize_dict(item) if isinstance(item, dict)
        else _sanitize_list(item) if isinstance(item, list)
        else item
        for item in items
    ]


def sanitize_model(model: object) -> object:
    """Sanitize all string fields in a Pydantic BaseModel.

    Returns a new model instance — the original is never mutated.
    """
    from pydantic import BaseModel

    if isinstance(model, BaseModel):
        data = model.model_dump()
        sanitized_data = sanitize_dict(data)
        return model.__class__(**sanitized_data)
    return model
