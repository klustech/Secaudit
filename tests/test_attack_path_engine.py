"""Tests for the attack path engine."""

from app.models.contract_info import ContractInfo
from app.models.function_info import FunctionInfo
from app.models.risk_flag import RiskFlag
from app.models.fund_flow import FundFlowEdge, FundFlowGraph
from app.models.attack_surface import Invariant, InvariantReport
from app.services.attack_path_engine import analyze_attack_surface


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
    defaults = {"name": "Vault", "file_path": "src/Vault.sol", "kind": "contract"}
    defaults.update(kwargs)
    return ContractInfo(**defaults)


def _empty_flows() -> FundFlowGraph:
    return FundFlowGraph()


def _empty_invariants() -> InvariantReport:
    return InvariantReport()


def test_reentrancy_detected():
    fn = _make_fn(
        name="withdraw",
        writes_state=True,
        external_calls=[".call{"],
        source="""
        (bool ok, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
        """,
    )
    report = analyze_attack_surface(
        [_make_contract()], [fn], [], _empty_flows(), _empty_invariants()
    )
    reent = [p for p in report.paths if p.risk_category == "reentrancy"]
    assert len(reent) >= 1
    assert reent[0].severity in ("critical", "high")


def test_no_reentrancy_with_guard():
    fn = _make_fn(
        name="withdraw",
        writes_state=True,
        modifiers=["nonReentrant"],
        external_calls=[".call{"],
        source="""
        nonReentrant
        (bool ok, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
        """,
    )
    report = analyze_attack_surface(
        [_make_contract()], [fn], [], _empty_flows(), _empty_invariants()
    )
    reent = [p for p in report.paths if p.risk_category == "reentrancy"]
    assert len(reent) == 0


def test_access_bypass_detected():
    fn = _make_fn(
        name="setOwner",
        writes_state=True,
        source="owner = newOwner;",
        token_actions=[],
    )
    flag = RiskFlag(
        severity="high",
        category="access-control",
        contract="Vault",
        function="setOwner",
        evidence="No access control on setOwner",
    )
    report = analyze_attack_surface(
        [_make_contract()], [fn], [flag], _empty_flows(), _empty_invariants()
    )
    bypass = [p for p in report.paths if p.risk_category == "access-bypass"]
    assert len(bypass) >= 1


def test_drain_path_from_unguarded_exit():
    fn = _make_fn(
        name="withdraw",
        source="token.transfer(msg.sender, amount);",
        token_actions=["transfer"],
    )
    flows = FundFlowGraph(
        exit_points=["Vault.withdraw"],
        unguarded_exits=["Vault.withdraw"],
        edges=[FundFlowEdge(
            source_contract="Vault",
            source_function="withdraw",
            mechanism="transfer",
            token="token",
            recipient="msg.sender",
            guarded=False,
            evidence="token.transfer(msg.sender, amount)",
        )],
    )
    report = analyze_attack_surface(
        [_make_contract()], [fn], [], flows, _empty_invariants()
    )
    drains = [p for p in report.paths if p.risk_category == "drain"]
    assert len(drains) >= 1
    assert drains[0].severity == "critical"  # msg.sender = arbitrary recipient


def test_invariant_violation_path():
    invariants = InvariantReport(
        invariants=[Invariant(
            contract="Vault",
            description="Users cannot withdraw more than balance",
            kind="balance",
            threatened_by=["Vault.withdraw"],
            evidence="Found balance check issue",
            manual_checks=["Check underflow"],
        )],
        broken_invariant_count=1,
    )
    report = analyze_attack_surface(
        [_make_contract()], [], [], _empty_flows(), invariants
    )
    inv_paths = [p for p in report.paths if "Invariant" in p.title]
    assert len(inv_paths) >= 1


def test_oracle_manipulation_path():
    fn = _make_fn(
        name="swap",
        source="(, int256 price, , , ) = priceFeed.latestRoundData();",
    )
    flag = RiskFlag(
        severity="medium",
        category="oracle-dependency",
        contract="Vault",
        function="swap",
        evidence="Oracle read in swap",
    )
    report = analyze_attack_surface(
        [_make_contract()], [fn], [flag], _empty_flows(), _empty_invariants()
    )
    oracle_paths = [p for p in report.paths if p.risk_category == "manipulation"]
    assert len(oracle_paths) >= 1


def test_replay_path_missing_nonce():
    fn = _make_fn(
        name="executeWithSig",
        source="address signer = ECDSA.recover(hash, sig);",
    )
    flag = RiskFlag(
        severity="medium",
        category="signature-auth",
        contract="Vault",
        function="executeWithSig",
        evidence="Signature verification",
    )
    report = analyze_attack_surface(
        [_make_contract()], [fn], [flag], _empty_flows(), _empty_invariants()
    )
    replay = [p for p in report.paths if p.risk_category == "replay"]
    assert len(replay) >= 1
    # Should mention missing nonce, deadline, chain ID
    assert any("nonce" in p.why_concerning for p in replay)


def test_unprotected_initializer_path():
    fn = _make_fn(
        name="initialize",
        writes_state=True,
        source="owner = _owner; token = _token;",
    )
    flag = RiskFlag(
        severity="high",
        category="initialization",
        contract="Vault",
        function="initialize",
        evidence="Initialization logic",
    )
    report = analyze_attack_surface(
        [_make_contract()], [fn], [flag], _empty_flows(), _empty_invariants()
    )
    init_paths = [p for p in report.paths if "initializer" in p.title.lower()]
    assert len(init_paths) >= 1
    assert init_paths[0].severity == "critical"


def test_summary_has_counts():
    report = analyze_attack_surface(
        [_make_contract()], [], [], _empty_flows(), _empty_invariants()
    )
    assert "0 critical" in report.summary


def test_deduplication():
    """Same title should not produce duplicate paths."""
    fn = _make_fn(
        name="withdraw",
        writes_state=True,
        external_calls=[".call{"],
        source="msg.sender.call{value: amount}(''); balances[msg.sender] -= amount;",
    )
    report = analyze_attack_surface(
        [_make_contract()], [fn, fn], [], _empty_flows(), _empty_invariants()
    )
    titles = [p.title for p in report.paths]
    assert len(titles) == len(set(titles))
