"""Tests for the canonical sanitization policy.

Covers:
- basic pattern replacement (parity with old test_safety_filter tests)
- idempotency: applying sanitize_text twice == once
- is_sanitized helper
- cross-layer consistency: same input → identical output regardless of helper used
- no double-mutation when data passes through multiple layers
- sanitize_model round-trip
- backward-compat re-export from safety_filter
"""

import pytest
from pydantic import BaseModel

from app.services.sanitization_policy import (
    contains_unsafe_terms,
    is_sanitized,
    sanitize_dict,
    sanitize_model,
    sanitize_text,
)


# ---------------------------------------------------------------------------
# Sample unsafe inputs used across multiple tests
# ---------------------------------------------------------------------------

_UNSAFE_STRINGS = [
    "This is an exploit path",
    "Found a drain path here",
    "Follow bypass steps to proceed",
    "attacker can steal funds",
    "Create PoC for this",
    "Craft a payload for testing",
    "Could weaponize this finding",
    "attacker could drain the pool",
    "attacker could manipulate price",
    "attacker can do X by calling Y",
    "proof of concept available",
    "exploit chain via reentrancy",
    "exploit flow through flash-loan",
    "exploit code snippet attached",
]

_SAFE_STRING = "Verify access control on withdraw function"


# ===== Basic replacement tests =====


@pytest.mark.parametrize("text", _UNSAFE_STRINGS)
def test_unsafe_strings_are_rewritten(text: str):
    result = sanitize_text(text)
    assert result != text, f"Expected rewrite for: {text!r}"


def test_safe_text_unchanged():
    assert sanitize_text(_SAFE_STRING) == _SAFE_STRING


# ===== Idempotency tests =====


@pytest.mark.parametrize("text", _UNSAFE_STRINGS)
def test_sanitize_text_is_idempotent(text: str):
    """Applying sanitize_text twice must yield the same result as once."""
    once = sanitize_text(text)
    twice = sanitize_text(once)
    assert once == twice, f"Double-sanitize mutated output for: {text!r}"


def test_sanitize_dict_is_idempotent():
    data = {
        "title": "exploit in withdraw",
        "steps": ["attacker can steal", "verify access"],
        "nested": {"note": "drain path found"},
    }
    once = sanitize_dict(data)
    twice = sanitize_dict(once)
    assert once == twice


def test_sanitize_text_idempotent_on_safe_text():
    assert sanitize_text(sanitize_text(_SAFE_STRING)) == _SAFE_STRING


# ===== is_sanitized / contains_unsafe_terms =====


@pytest.mark.parametrize("text", _UNSAFE_STRINGS)
def test_contains_unsafe_terms_positive(text: str):
    assert contains_unsafe_terms(text)


def test_contains_unsafe_terms_negative():
    assert not contains_unsafe_terms(_SAFE_STRING)


@pytest.mark.parametrize("text", _UNSAFE_STRINGS)
def test_is_sanitized_after_sanitize(text: str):
    """After sanitization, is_sanitized must return True."""
    assert is_sanitized(sanitize_text(text))


def test_is_sanitized_on_safe_text():
    assert is_sanitized(_SAFE_STRING)


# ===== Cross-layer consistency =====


def test_dict_and_text_produce_same_results():
    """sanitize_dict on a flat dict must equal sanitize_text on each value."""
    data = {"a": "exploit path here", "b": "attacker can drain"}
    dict_result = sanitize_dict(data)
    for key, value in data.items():
        assert dict_result[key] == sanitize_text(value)


class _DummyModel(BaseModel):
    title: str
    notes: list[str] = []


def test_model_and_dict_produce_same_results():
    """sanitize_model must produce the same strings as sanitize_dict."""
    model = _DummyModel(title="exploit in withdraw", notes=["attacker can steal"])
    sanitized_model = sanitize_model(model)
    sanitized_dict = sanitize_dict(model.model_dump())

    assert sanitized_model.title == sanitized_dict["title"]
    assert sanitized_model.notes == sanitized_dict["notes"]


# ===== No double-mutation through layers =====


def test_no_double_mutation_pipeline_then_api():
    """Simulates pipeline sanitization then API defense-in-depth pass.

    The second pass must be a no-op.
    """
    raw = {
        "title": "exploit chain found",
        "steps": ["attacker could drain via flash-loan"],
        "nested": {"note": "PoC available"},
    }
    # Pipeline pass (source of truth)
    after_pipeline = sanitize_dict(raw)
    # API pass (defense-in-depth)
    after_api = sanitize_dict(after_pipeline)

    assert after_pipeline == after_api


def test_no_double_mutation_model_then_dict():
    """sanitize_model then sanitize_dict must not change output."""
    model = _DummyModel(title="drain path via exploit", notes=["payload crafted"])
    after_model = sanitize_model(model)
    after_dict = sanitize_dict(after_model.model_dump())

    assert after_model.title == after_dict["title"]
    assert after_model.notes == after_dict["notes"]


# ===== sanitize_dict structure preservation =====


def test_sanitize_dict_preserves_structure():
    data = {
        "title": "exploit in withdraw",
        "count": 42,
        "active": True,
        "steps": ["attacker can steal", "verify access"],
        "nested": {"note": "drain path found", "score": 3.14},
    }
    result = sanitize_dict(data)
    assert isinstance(result["count"], int)
    assert isinstance(result["active"], bool)
    assert isinstance(result["nested"]["score"], float)
    assert len(result["steps"]) == 2


# ===== Backward-compatible re-export =====


def test_safety_filter_reexport():
    """Importing from safety_filter must yield the same functions."""
    from app.services.safety_filter import (
        sanitize_text as sf_sanitize_text,
        sanitize_dict as sf_sanitize_dict,
        contains_unsafe_terms as sf_contains_unsafe,
        is_sanitized as sf_is_sanitized,
    )
    text = "exploit path here"
    assert sf_sanitize_text(text) == sanitize_text(text)
    assert sf_contains_unsafe(text) == contains_unsafe_terms(text)
    assert sf_is_sanitized(text) == is_sanitized(text)
    data = {"a": text}
    assert sf_sanitize_dict(data) == sanitize_dict(data)
