"""Tests for the value movement mapper."""

from app.models.contract_info import ContractInfo
from app.models.function_info import FunctionInfo
from app.services.value_movement_mapper import analyze_value_movements


def _make_fn(**kwargs) -> FunctionInfo:
    defaults = {
        "contract": "Vault",
        "file_path": "src/Vault.sol",
        "name": "test",
        "signature": "test()",
        "visibility": "external",
        "mutability": "nonpayable",
        "modifiers": [],
        "writes_state": False,
        "external_calls": [],
        "token_actions": [],
        "source": "",
    }
    defaults.update(kwargs)
    return FunctionInfo(**defaults)


def _make_contract(**kwargs) -> ContractInfo:
    defaults = {
        "name": "Vault",
        "file_path": "src/Vault.sol",
        "kind": "contract",
    }
    defaults.update(kwargs)
    return ContractInfo(**defaults)


def test_deposit_detected_as_inflow():
    fn = _make_fn(
        name="deposit",
        mutability="nonpayable",
        source="token.transferFrom(msg.sender, address(this), amount); balances[msg.sender] += amount;",
        writes_state=True,
        token_actions=["transferFrom"],
    )
    report = analyze_value_movements([_make_contract()], [fn])
    inflows = [e for e in report.edges if e.direction == "inflow"]
    assert len(inflows) >= 1
    assert inflows[0].asset_type == "erc20"


def test_payable_function_is_inflow():
    fn = _make_fn(
        name="receive",
        mutability="payable",
        source="balances[msg.sender] += msg.value;",
        writes_state=True,
    )
    report = analyze_value_movements([_make_contract()], [fn])
    inflows = [e for e in report.edges if e.direction == "inflow"]
    assert len(inflows) >= 1
    assert inflows[0].asset_type == "eth"


def test_withdraw_detected_as_outflow():
    fn = _make_fn(
        name="withdraw",
        source="token.transfer(msg.sender, amount); balances[msg.sender] -= amount;",
        writes_state=True,
        token_actions=["transfer"],
    )
    report = analyze_value_movements([_make_contract()], [fn])
    outflows = [e for e in report.edges if e.direction == "outflow"]
    assert len(outflows) >= 1
    assert outflows[0].asset_type == "erc20"


def test_unguarded_outflow_flagged():
    fn = _make_fn(
        name="withdraw",
        source="token.transfer(msg.sender, amount);",
        token_actions=["transfer"],
    )
    report = analyze_value_movements([_make_contract()], [fn])
    outflows = [e for e in report.edges if e.direction == "outflow"]
    assert len(outflows) >= 1
    assert outflows[0].access_controlled is False
    assert any("authorization" in c.lower() or "recipient" in c.lower()
               for c in outflows[0].manual_checks)


def test_guarded_outflow_marked():
    fn = _make_fn(
        name="withdraw",
        modifiers=["onlyOwner"],
        source="token.transfer(msg.sender, amount);",
        token_actions=["transfer"],
    )
    report = analyze_value_movements([_make_contract()], [fn])
    outflows = [e for e in report.edges if e.direction == "outflow"]
    assert len(outflows) >= 1
    assert outflows[0].access_controlled is True


def test_eth_transfer_edge_extracted():
    fn = _make_fn(
        name="sweepETH",
        source='(bool ok, ) = owner.call{value: address(this).balance}("");',
        external_calls=[".call{"],
    )
    report = analyze_value_movements([_make_contract()], [fn])
    eth_edges = [e for e in report.edges if e.asset_type == "eth" and e.direction == "outflow"]
    assert len(eth_edges) >= 1
    assert eth_edges[0].mechanism == "call{value}"


def test_approve_edge_extracted():
    fn = _make_fn(
        name="approveRouter",
        source="token.approve(router, type(uint256).max);",
        token_actions=["approve"],
    )
    report = analyze_value_movements([_make_contract()], [fn])
    approvals = [e for e in report.edges if e.direction == "approval"]
    assert len(approvals) >= 1
    assert "delegated spending" in approvals[0].notes[0].lower()


def test_caller_influenced_detected():
    fn = _make_fn(
        name="withdraw",
        source="token.transfer(msg.sender, amount);",
        token_actions=["transfer"],
    )
    report = analyze_value_movements([_make_contract()], [fn])
    outflows = [e for e in report.edges if e.direction == "outflow"]
    assert len(outflows) >= 1
    assert outflows[0].caller_influenced is True


def test_summary_contains_counts():
    fn = _make_fn(
        name="withdraw",
        source="token.transfer(msg.sender, amount);",
        token_actions=["transfer"],
    )
    report = analyze_value_movements([_make_contract()], [fn])
    summary_text = " ".join(report.summary)
    assert "outflow" in summary_text.lower()


def test_no_exploit_terms_in_output():
    """Output must not contain exploit-oriented terminology."""
    fn = _make_fn(
        name="withdraw",
        source="token.transfer(msg.sender, amount);",
        token_actions=["transfer"],
    )
    report = analyze_value_movements([_make_contract()], [fn])
    all_text = " ".join(
        str(e.model_dump()) for e in report.edges
    ) + " ".join(report.summary)
    banned = ["exploit", "drain path", "bypass steps", "attacker can do",
              "proof of concept", "payload", "weaponize"]
    for term in banned:
        assert term not in all_text.lower()


def test_output_is_review_oriented():
    """Output should contain review-oriented language."""
    fn = _make_fn(
        name="withdraw",
        source="token.transfer(msg.sender, amount);",
        token_actions=["transfer"],
    )
    report = analyze_value_movements([_make_contract()], [fn])
    all_checks = []
    for e in report.edges:
        all_checks.extend(e.manual_checks)
    checks_text = " ".join(all_checks).lower()
    assert "verify" in checks_text or "check" in checks_text
