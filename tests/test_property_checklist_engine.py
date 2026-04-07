"""Tests for the property checklist engine."""

from app.models.contract_info import ContractInfo
from app.models.function_info import FunctionInfo
from app.services.property_checklist_engine import infer_review_properties


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


def test_balance_property_inferred():
    contract = _make_contract(state_vars=["balances", "totalDeposits"])
    fn = _make_fn(
        name="deposit",
        writes_state=True,
        source="balances[msg.sender] += amount; totalDeposits += amount;",
    )
    report = infer_review_properties([contract], [fn])
    balance_props = [p for p in report.properties if p.kind == "balance"]
    assert len(balance_props) >= 1
    assert any("totalDeposits" in p.statement for p in balance_props)


def test_withdrawal_property_inferred():
    contract = _make_contract(state_vars=["balances"])
    fn = _make_fn(
        name="withdraw",
        visibility="external",
        writes_state=True,
        source="balances[msg.sender] -= amount; token.transfer(msg.sender, amount);",
        token_actions=["transfer"],
    )
    report = infer_review_properties([contract], [fn])
    withdraw_props = [p for p in report.properties
                      if "withdraw" in p.statement.lower() or "entitlement" in p.statement.lower()]
    assert len(withdraw_props) >= 1
    assert "Vault.withdraw" in withdraw_props[0].related_functions


def test_access_property_inferred():
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
    report = infer_review_properties([contract], [admin_fn, unguarded_fn])
    access_props = [p for p in report.properties if p.kind == "access"]
    assert len(access_props) >= 1
    assert any("Vault.setOwner" in p.related_functions for p in access_props)


def test_supply_property_with_mint():
    contract = _make_contract(state_vars=["totalSupply"])
    mint_fn = _make_fn(
        name="mint",
        writes_state=True,
        source="totalSupply += amount; balances[to] += amount;",
    )
    report = infer_review_properties([contract], [mint_fn])
    supply_props = [p for p in report.properties if p.kind == "supply"]
    assert len(supply_props) >= 1


def test_share_price_property():
    contract = _make_contract(state_vars=["totalSupply", "totalAssets"])
    fn = _make_fn(
        name="deposit",
        writes_state=True,
        source="uint256 shares = convertToAssets(amount); totalAssets += amount;",
        token_actions=["transfer"],
    )
    report = infer_review_properties([contract], [fn])
    share_props = [p for p in report.properties
                   if "share price" in p.statement.lower() or "exchange rate" in p.statement.lower()]
    assert len(share_props) >= 1


def test_init_property():
    contract = _make_contract()
    fn = _make_fn(
        name="initialize",
        visibility="external",
        writes_state=True,
        source="owner = _owner; initialized = true;",
    )
    report = infer_review_properties([contract], [fn])
    init_props = [p for p in report.properties if p.kind == "initialization"]
    assert len(init_props) >= 1
    assert "Vault.initialize" in init_props[0].related_functions


def test_nonce_property():
    contract = _make_contract(state_vars=["nonces"])
    fn = _make_fn(
        name="permit",
        writes_state=True,
        source="require(nonce == nonces[owner]); nonces[owner]++;",
    )
    report = infer_review_properties([contract], [fn])
    nonce_props = [p for p in report.properties if p.kind == "ordering"]
    assert len(nonce_props) >= 1


def test_interface_contracts_skipped():
    contract = _make_contract(kind="interface")
    fn = _make_fn(source="totalSupply; balances; nonce;")
    report = infer_review_properties([contract], [fn])
    assert len(report.properties) == 0


def test_oracle_property():
    contract = _make_contract()
    fn = _make_fn(
        name="swap",
        source="(, int256 price, , , ) = priceFeed.latestRoundData();",
    )
    report = infer_review_properties([contract], [fn])
    oracle_props = [p for p in report.properties if p.kind == "oracle"]
    assert len(oracle_props) >= 1
    assert "freshness" in oracle_props[0].statement.lower()


def test_signature_property():
    contract = _make_contract()
    fn = _make_fn(
        name="executeWithSig",
        source="address signer = ECDSA.recover(hash, sig);",
    )
    report = infer_review_properties([contract], [fn])
    sig_props = [p for p in report.properties if p.kind == "signature"]
    assert len(sig_props) >= 1


def test_no_violation_claims():
    """Properties should never claim a violation — only suggest verification."""
    contract = _make_contract(state_vars=["balances", "totalDeposits"])
    fn = _make_fn(
        name="withdraw",
        visibility="external",
        writes_state=True,
        source="balances[msg.sender] -= amount;",
    )
    report = infer_review_properties([contract], [fn])
    all_text = " ".join(str(p.model_dump()) for p in report.properties)
    assert "violated" not in all_text.lower()
    assert "broken" not in all_text.lower()


def test_no_exploit_terms():
    """Output must not contain exploit-oriented terminology."""
    contract = _make_contract(state_vars=["balances"])
    fn = _make_fn(
        name="withdraw",
        writes_state=True,
        source="balances[msg.sender] -= amount;",
    )
    report = infer_review_properties([contract], [fn])
    all_text = " ".join(str(p.model_dump()) for p in report.properties)
    banned = ["exploit", "drain path", "bypass steps", "attacker can do",
              "proof of concept", "payload", "weaponize"]
    for term in banned:
        assert term not in all_text.lower()
