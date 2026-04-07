"""Tests for the risk scenario engine."""

from app.models.contract_info import ContractInfo
from app.models.function_info import FunctionInfo
from app.models.risk_flag import RiskFlag
from app.models.value_movement import ValueMovementEdge, ValueMovementReport
from app.models.review_property import ReviewProperty, PropertyChecklistReport
from app.services.risk_scenario_engine import generate_risk_scenarios


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


def _empty_vm() -> ValueMovementReport:
    return ValueMovementReport()


def _empty_props() -> PropertyChecklistReport:
    return PropertyChecklistReport()


def test_authorization_scenario_from_access_flag():
    flag = RiskFlag(
        severity="high",
        category="access-control",
        contract="Vault",
        function="setOwner",
        evidence="No access control on setOwner",
    )
    report = generate_risk_scenarios([flag], _empty_vm(), _empty_props())
    auth = [s for s in report.scenarios if s.category == "authorization"]
    assert len(auth) >= 1
    assert "authorization" in auth[0].title.lower() or "requires review" in auth[0].title.lower()


def test_external_interaction_scenario():
    flag = RiskFlag(
        severity="medium",
        category="external-call",
        contract="Vault",
        function="withdraw",
        evidence="External call in withdraw",
    )
    report = generate_risk_scenarios([flag], _empty_vm(), _empty_props())
    ext = [s for s in report.scenarios if s.category == "external-interaction"]
    assert len(ext) >= 1


def test_accounting_scenario_from_funds_flow():
    flag = RiskFlag(
        severity="high",
        category="funds-flow",
        contract="Vault",
        function="withdraw",
        evidence="Token transfer in withdraw",
    )
    report = generate_risk_scenarios([flag], _empty_vm(), _empty_props())
    acct = [s for s in report.scenarios if s.category == "accounting"]
    assert len(acct) >= 1


def test_oracle_scenario():
    flag = RiskFlag(
        severity="medium",
        category="oracle-dependency",
        contract="Vault",
        function="swap",
        evidence="Oracle read in swap",
    )
    report = generate_risk_scenarios([flag], _empty_vm(), _empty_props())
    oracle = [s for s in report.scenarios if s.category == "oracle"]
    assert len(oracle) >= 1
    assert "freshness" in oracle[0].why_it_matters.lower()


def test_signature_scenario():
    flag = RiskFlag(
        severity="medium",
        category="signature-auth",
        contract="Vault",
        function="executeWithSig",
        evidence="Signature verification",
    )
    report = generate_risk_scenarios([flag], _empty_vm(), _empty_props())
    sig = [s for s in report.scenarios if s.category == "signatures"]
    assert len(sig) >= 1
    assert "nonce" in sig[0].why_it_matters.lower() or "nonce" in " ".join(sig[0].manual_validation_steps).lower()


def test_initialization_scenario():
    flag = RiskFlag(
        severity="high",
        category="initialization",
        contract="Vault",
        function="initialize",
        evidence="Initialization logic",
    )
    report = generate_risk_scenarios([flag], _empty_vm(), _empty_props())
    init = [s for s in report.scenarios if s.category == "initialization"]
    assert len(init) >= 1


def test_scenario_from_unguarded_outflow():
    vm = ValueMovementReport(edges=[
        ValueMovementEdge(
            contract="Vault",
            function="withdraw",
            direction="outflow",
            asset_type="erc20",
            mechanism="transfer",
            destination_hint="msg.sender",
            caller_influenced=True,
            access_controlled=False,
            external_interaction=True,
        ),
    ])
    report = generate_risk_scenarios([], vm, _empty_props())
    auth = [s for s in report.scenarios if s.category == "authorization"]
    assert len(auth) >= 1


def test_scenario_from_property():
    props = PropertyChecklistReport(properties=[
        ReviewProperty(
            kind="balance",
            statement="User withdrawals should not exceed recorded entitlement",
            rationale="Balance mapping and withdrawal found",
            related_functions=["Vault.withdraw"],
            confidence="high",
            manual_checks=["Verify balance check before transfer"],
        ),
    ])
    report = generate_risk_scenarios([], _empty_vm(), props)
    prop_scenarios = [s for s in report.scenarios if "Property review" in s.title]
    assert len(prop_scenarios) >= 1


def test_deduplication():
    """Same title should not produce duplicate scenarios."""
    flag = RiskFlag(
        severity="high",
        category="access-control",
        contract="Vault",
        function="setOwner",
        evidence="No access control on setOwner",
    )
    report = generate_risk_scenarios([flag, flag], _empty_vm(), _empty_props())
    titles = [s.title for s in report.scenarios]
    assert len(titles) == len(set(titles))


def test_summary_has_counts():
    report = generate_risk_scenarios([], _empty_vm(), _empty_props())
    assert any("0" in s or "scenario" in s.lower() for s in report.summary)


def test_no_exploit_terms():
    """Output must not contain exploit-oriented terminology."""
    flag = RiskFlag(
        severity="high",
        category="access-control",
        contract="Vault",
        function="setOwner",
        evidence="No access control on setOwner",
    )
    vm = ValueMovementReport(edges=[
        ValueMovementEdge(
            contract="Vault",
            function="withdraw",
            direction="outflow",
            asset_type="erc20",
            mechanism="transfer",
            destination_hint="msg.sender",
            caller_influenced=True,
            access_controlled=False,
            external_interaction=True,
        ),
    ])
    report = generate_risk_scenarios([flag], vm, _empty_props())
    all_text = " ".join(str(s.model_dump()) for s in report.scenarios)
    banned = ["exploit", "drain path", "bypass steps", "attacker can do",
              "proof of concept", "payload", "weaponize", "attacker"]
    for term in banned:
        assert term not in all_text.lower()


def test_no_attacker_instructions():
    """Scenarios must not contain attacker action descriptions."""
    flag = RiskFlag(
        severity="high",
        category="funds-flow",
        contract="Vault",
        function="withdraw",
        evidence="Token transfer in withdraw",
    )
    report = generate_risk_scenarios([flag], _empty_vm(), _empty_props())
    for scenario in report.scenarios:
        all_text = " ".join([
            scenario.title, scenario.risky_assumption, scenario.why_it_matters,
            *scenario.manual_validation_steps, *scenario.remediation_themes,
        ]).lower()
        assert "attacker" not in all_text
        assert "exploit" not in all_text
        assert "bypass chain" not in all_text
        assert "poc" not in all_text


def test_only_review_oriented_output():
    """All scenarios should use review-oriented language."""
    flag = RiskFlag(
        severity="high",
        category="access-control",
        contract="Vault",
        function="setOwner",
        evidence="No access control",
    )
    report = generate_risk_scenarios([flag], _empty_vm(), _empty_props())
    for scenario in report.scenarios:
        all_steps = " ".join(scenario.manual_validation_steps).lower()
        assert "verify" in all_steps or "check" in all_steps or "confirm" in all_steps
