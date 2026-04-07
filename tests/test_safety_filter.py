"""Tests for the safety output filter."""

from app.services.safety_filter import sanitize_text, contains_unsafe_terms, sanitize_dict


def test_exploit_replaced():
    assert "exploit" not in sanitize_text("This is an exploit path")
    assert "requires review" in sanitize_text("This is an exploit path")


def test_drain_path_replaced():
    assert "drain path" not in sanitize_text("Found a drain path here")
    assert "requires review" in sanitize_text("Found a drain path here")


def test_bypass_steps_replaced():
    assert "bypass steps" not in sanitize_text("Follow bypass steps")
    assert "should be validated" in sanitize_text("Follow bypass steps")


def test_attacker_can_replaced():
    result = sanitize_text("attacker can steal funds")
    assert "attacker can" not in result
    assert "may affect" in result


def test_poc_replaced():
    assert "PoC" not in sanitize_text("Create PoC for this")
    assert "manual confirmation needed" in sanitize_text("Create PoC for this")


def test_payload_replaced():
    assert "payload" not in sanitize_text("Craft a payload")
    assert "should be validated" in sanitize_text("Craft a payload")


def test_weaponize_replaced():
    assert "weaponize" not in sanitize_text("Could weaponize this finding")
    assert "requires review" in sanitize_text("Could weaponize this finding")


def test_safe_text_unchanged():
    safe = "Verify access control on withdraw function"
    assert sanitize_text(safe) == safe


def test_contains_unsafe_terms_detection():
    assert contains_unsafe_terms("This is an exploit")
    assert contains_unsafe_terms("drain path detected")
    assert not contains_unsafe_terms("Verify access control")


def test_sanitize_dict():
    data = {
        "title": "exploit in withdraw",
        "steps": ["attacker can steal", "verify access"],
        "nested": {"note": "drain path found"},
    }
    result = sanitize_dict(data)
    assert "exploit" not in result["title"]
    assert "attacker can" not in result["steps"][0]
    assert "drain path" not in result["nested"]["note"]
    # Safe text unchanged
    assert result["steps"][1] == "verify access"
