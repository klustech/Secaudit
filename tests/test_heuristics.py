"""Tests for the heuristics engine."""

from app.models.function_info import FunctionInfo
from app.services.heuristics_engine import analyze_function


def _make_fn(**kwargs) -> FunctionInfo:
    defaults = {
        "contract": "TestContract",
        "file_path": "src/Test.sol",
        "name": "testFn",
        "signature": "testFn()",
        "visibility": "public",
        "mutability": "nonpayable",
        "modifiers": [],
        "writes_state": False,
        "external_calls": [],
        "token_actions": [],
        "source": "",
    }
    defaults.update(kwargs)
    return FunctionInfo(**defaults)


def test_no_flags_on_safe_function():
    fn = _make_fn(visibility="internal", writes_state=False)
    flags = analyze_function(fn)
    assert len(flags) == 0


def test_access_control_flag_on_unprotected_write():
    fn = _make_fn(visibility="external", writes_state=True, source="owner = msg.sender;")
    flags = analyze_function(fn)
    categories = [f.category for f in flags]
    assert "access-control" in categories


def test_no_access_flag_when_modifier_present():
    fn = _make_fn(
        visibility="external",
        writes_state=True,
        modifiers=["onlyOwner"],
        source="owner = newOwner;",
    )
    flags = analyze_function(fn)
    # Should not flag access-control since onlyOwner is present
    ac_flags = [f for f in flags if f.category == "access-control"
                and "writes state with no obvious access control" in f.evidence]
    assert len(ac_flags) == 0


def test_fund_movement_flag():
    fn = _make_fn(
        visibility="external",
        token_actions=["transfer"],
        source="token.transfer(to, amount);",
    )
    flags = analyze_function(fn)
    categories = [f.category for f in flags]
    assert "funds-flow" in categories


def test_external_call_flag():
    fn = _make_fn(
        visibility="public",
        external_calls=[".call("],
        source="target.call{value: amount}(data);",
    )
    flags = analyze_function(fn)
    categories = [f.category for f in flags]
    assert "external-call" in categories


def test_upgrade_flag():
    fn = _make_fn(
        name="upgradeTo",
        visibility="external",
        writes_state=True,
        source="function upgradeTo(address newImpl) external { _setImplementation(newImpl); }",
    )
    flags = analyze_function(fn)
    categories = [f.category for f in flags]
    assert "upgradeability" in categories


def test_initialization_flag():
    fn = _make_fn(
        name="initialize",
        visibility="external",
        writes_state=True,
        source="function initialize(address _owner) external initializer { owner = _owner; }",
    )
    flags = analyze_function(fn)
    categories = [f.category for f in flags]
    assert "initialization" in categories


def test_oracle_flag():
    fn = _make_fn(
        source="(, int256 price, , , ) = priceFeed.latestRoundData();",
    )
    flags = analyze_function(fn)
    categories = [f.category for f in flags]
    assert "oracle-dependency" in categories


def test_signature_flag():
    fn = _make_fn(
        source="address signer = ECDSA.recover(hash, signature);",
    )
    flags = analyze_function(fn)
    categories = [f.category for f in flags]
    assert "signature-auth" in categories
