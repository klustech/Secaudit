"""Tests for the fund flow analyzer."""

from app.models.contract_info import ContractInfo
from app.models.function_info import FunctionInfo
from app.services.fund_flow_analyzer import analyze_fund_flows


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


def test_deposit_detected_as_entry_point():
    fn = _make_fn(
        name="deposit",
        mutability="nonpayable",
        source="token.transferFrom(msg.sender, address(this), amount); balances[msg.sender] += amount;",
        writes_state=True,
        token_actions=["transferFrom"],
    )
    graph = analyze_fund_flows([_make_contract()], [fn])
    assert "Vault.deposit" in graph.entry_points


def test_payable_function_is_entry_point():
    fn = _make_fn(
        name="receive",
        mutability="payable",
        source="balances[msg.sender] += msg.value;",
        writes_state=True,
    )
    graph = analyze_fund_flows([_make_contract()], [fn])
    assert "Vault.receive" in graph.entry_points


def test_withdraw_detected_as_exit_point():
    fn = _make_fn(
        name="withdraw",
        source="token.transfer(msg.sender, amount); balances[msg.sender] -= amount;",
        writes_state=True,
        token_actions=["transfer"],
    )
    graph = analyze_fund_flows([_make_contract()], [fn])
    assert "Vault.withdraw" in graph.exit_points


def test_unguarded_exit_detected():
    fn = _make_fn(
        name="withdraw",
        source="token.transfer(msg.sender, amount);",
        token_actions=["transfer"],
    )
    graph = analyze_fund_flows([_make_contract()], [fn])
    assert "Vault.withdraw" in graph.unguarded_exits


def test_guarded_exit_not_flagged_as_unguarded():
    fn = _make_fn(
        name="withdraw",
        modifiers=["onlyOwner"],
        source="token.transfer(msg.sender, amount);",
        token_actions=["transfer"],
    )
    graph = analyze_fund_flows([_make_contract()], [fn])
    assert "Vault.withdraw" in graph.exit_points
    assert "Vault.withdraw" not in graph.unguarded_exits


def test_eth_transfer_edge_extracted():
    fn = _make_fn(
        name="sweepETH",
        source='(bool ok, ) = owner.call{value: address(this).balance}("");',
        external_calls=[".call{"],
    )
    graph = analyze_fund_flows([_make_contract()], [fn])
    eth_edges = [e for e in graph.edges if e.token == "ETH"]
    assert len(eth_edges) >= 1
    assert eth_edges[0].mechanism == "call{value}"


def test_erc20_transfer_edge_extracted():
    fn = _make_fn(
        name="withdraw",
        source="token.transfer(msg.sender, amount);",
        token_actions=["transfer"],
    )
    graph = analyze_fund_flows([_make_contract()], [fn])
    transfer_edges = [e for e in graph.edges if e.mechanism == "transfer"]
    assert len(transfer_edges) >= 1
    assert transfer_edges[0].token == "token"


def test_approve_edge_extracted():
    fn = _make_fn(
        name="approveRouter",
        source="token.approve(router, type(uint256).max);",
        token_actions=["approve"],
    )
    graph = analyze_fund_flows([_make_contract()], [fn])
    approve_edges = [e for e in graph.edges if e.mechanism == "approve"]
    assert len(approve_edges) >= 1


def test_summary_contains_counts():
    fn = _make_fn(
        name="withdraw",
        source="token.transfer(msg.sender, amount);",
        token_actions=["transfer"],
    )
    graph = analyze_fund_flows([_make_contract()], [fn])
    assert "Entry points" in graph.summary
    assert "Exit points" in graph.summary
