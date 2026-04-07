"""Safety output filter — rejects or rewrites text containing exploit-oriented terms.

This lint rule runs over all generated text to ensure outputs remain
review-oriented and non-weaponized.
"""

from __future__ import annotations

import re

# Terms that should be replaced in generated text
_UNSAFE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\bexploit\b', re.IGNORECASE), "requires review"),
    (re.compile(r'\bdrain path\b', re.IGNORECASE), "requires review"),
    (re.compile(r'\bbypass steps?\b', re.IGNORECASE), "should be validated"),
    (re.compile(r'\battacker can do .+? by\b', re.IGNORECASE), "manual confirmation needed"),
    (re.compile(r'\bproof of concept\b', re.IGNORECASE), "manual confirmation needed"),
    (re.compile(r'\bpayload\b', re.IGNORECASE), "should be validated"),
    (re.compile(r'\bweaponize\b', re.IGNORECASE), "requires review"),
    (re.compile(r'\battacker could drain\b', re.IGNORECASE), "may affect accounting/safety"),
    (re.compile(r'\battacker could\b', re.IGNORECASE), "may affect authorization/accounting/safety"),
    (re.compile(r'\battacker can\b', re.IGNORECASE), "may affect authorization/accounting/safety"),
    (re.compile(r'\bexploit chain\b', re.IGNORECASE), "requires review"),
    (re.compile(r'\bexploit flow\b', re.IGNORECASE), "requires review"),
    (re.compile(r'\bexploit code\b', re.IGNORECASE), "requires review"),
    (re.compile(r'\bPoC\b'), "manual confirmation needed"),
]


def sanitize_text(text: str) -> str:
    """Replace unsafe exploit-oriented terms with safe review-oriented alternatives."""
    for pattern, replacement in _UNSAFE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def contains_unsafe_terms(text: str) -> bool:
    """Check if text contains any unsafe exploit-oriented terms."""
    for pattern, _ in _UNSAFE_PATTERNS:
        if pattern.search(text):
            return True
    return False


def sanitize_dict(data: dict) -> dict:
    """Recursively sanitize all string values in a dictionary."""
    sanitized = {}
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
    """Sanitize all string fields in a Pydantic model by returning a sanitized copy.

    Works with any Pydantic BaseModel by dumping to dict, sanitizing, and
    reconstructing.
    """
    from pydantic import BaseModel
    if isinstance(model, BaseModel):
        data = model.model_dump()
        sanitized_data = sanitize_dict(data)
        return model.__class__(**sanitized_data)
    return model
