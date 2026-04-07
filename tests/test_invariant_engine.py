"""Tests for the invariant engine."""

from app.models.contract_info import ContractInfo
from app.models.function_info import FunctionInfo
from app.models.risk_flag import RiskFlag
from app.services.invariant_engine import infer_invariants


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
        "state_vars": [],
    }
    defaults.update(kwargs)
    return ContractInfo(**defaults)


def test_balance_conservation_invariant():
    contract = _make_contract(state_vars=["balances", "totalDeposits"])
    fn = _make_fn(
        name="deposit",
        writes_state=True,
        source="balances[msg.sender] += amount; totalDeposits += amount;",
    )
    report = infer_invariants([contract], [fn], [])
    balance_invs = [i for i in report.invariants if i.kind == "balance"]
    assert len(balance_invs) >= 1
    assert any("totalDeposits" in i.description for i in balance_invs)


def test_withdrawal_invariant():
    contract = _make_contract(state_vars=["balances"])
    fn = _make_fn(
        name="withdraw",
        visibility="external",
        writes_state=True,
        source="balances[msg.sender] -= amount; token.transfer(msg.sender, amount);",
        token_actions=["transfer"],
    )
    report = infer_invariants([contract], [fn], [])
    withdraw_invs = [i for i in report.invariants
                     if "withdraw more" in i.description.lower()]
    assert len(withdraw_invs) >= 1
    assert "Vault.withdraw" in withdraw_invs[0].threatened_by


def test_access_control_invariant():
    contract = _make_contract(state_vars=["owner"])
    admin_fn = _make_fn(
        name="setFee",
        modifiers=["onlyOwner"],
        writes_state=True,
        source="fee = newFee; onlyOwner",
    )
    unguarded_fn = _make_fn(
        name="setOwner",
        visibility="external",
        writes_state=True,
        source="owner = newOwner;",
    )
    report = infer_invariants([contract], [admin_fn, unguarded_fn], [])
    access_invs = [i for i in report.invariants if i.kind == "access"]
    assert len(access_invs) >= 1
    # setOwner should threaten the access invariant (writes to owner, no guard)
    assert any("Vault.setOwner" in i.threatened_by for i in access_invs)


def test_supply_invariant_with_mint():
    contract = _make_contract(state_vars=["totalSupply"])
    mint_fn = _make_fn(
        name="mint",
        writes_state=True,
        source="totalSupply += amount; balances[to] += amount;",
    )
    report = infer_invariants([contract], [mint_fn], [])
    supply_invs = [i for i in report.invariants if i.kind == "supply"]
    assert len(supply_invs) >= 1


def test_share_price_invariant():
    contract = _make_contract(state_vars=["totalSupply", "totalAssets"])
    fn = _make_fn(
        name="deposit",
        writes_state=True,
        source="uint256 shares = convertToAssets(amount); totalAssets += amount;",
        token_actions=["transfer"],
    )
    report = infer_invariants([contract], [fn], [])
    share_invs = [i for i in report.invariants
                  if "share price" in i.description.lower() or "exchange rate" in i.description.lower()]
    assert len(share_invs) >= 1


def test_init_invariant():
    contract = _make_contract()
    fn = _make_fn(
        name="initialize",
        visibility="external",
        writes_state=True,
        source="owner = _owner; initialized = true;",
    )
    report = infer_invariants([contract], [fn], [])
    init_invs = [i for i in report.invariants if i.kind == "state"]
    assert len(init_invs) >= 1
    assert "Vault.initialize" in init_invs[0].threatened_by


def test_nonce_invariant():
    contract = _make_contract(state_vars=["nonces"])
    fn = _make_fn(
        name="permit",
        writes_state=True,
        source="require(nonce == nonces[owner]); nonces[owner]++;",
    )
    report = infer_invariants([contract], [fn], [])
    nonce_invs = [i for i in report.invariants if i.kind == "ordering"]
    assert len(nonce_invs) >= 1


def test_interface_contracts_skipped():
    contract = _make_contract(kind="interface")
    fn = _make_fn(source="totalSupply; balances; nonce;")
    report = infer_invariants([contract], [fn], [])
    assert len(report.invariants) == 0


def test_broken_count_accurate():
    contract = _make_contract(state_vars=["balances"])
    fn = _make_fn(
        name="withdraw",
        visibility="external",
        writes_state=True,
        source="balances[msg.sender] -= amount;",
    )
    report = infer_invariants([contract], [fn], [])
    threatened = [i for i in report.invariants if i.threatened_by]
    assert report.broken_invariant_count == len(threatened)
