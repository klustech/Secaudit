"""Risk scenario engine — generates non-weaponized review scenarios.

Replaces attack_path_engine.py. Outputs explain why a pattern matters
and what to verify manually. Never outputs exploit flows, attacker actions,
bypass chains, or PoC ideas.
"""

from __future__ import annotations

import re

from app.models.contract_info import ContractInfo
from app.models.function_info import FunctionInfo
from app.models.risk_flag import RiskFlag
from app.models.value_movement import ValueMovementReport
from app.models.review_property import PropertyChecklistReport
from app.models.risk_scenario import RiskScenario, RiskScenarioReport

# --- Heuristic-to-scenario category mapping (safe mappings only) ---
_CATEGORY_MAP: dict[str, str] = {
    "access-control": "authorization",
    "external-call": "external-interaction",
    "funds-flow": "accounting",
    "initialization": "initialization",
    "upgradeability": "upgradeability",
    "oracle-dependency": "oracle",
    "signature-auth": "signatures",
    "timelock-queue": "timelock",
}


class RiskScenarioEngine:
    """Generate non-weaponized review scenarios from analysis evidence."""

    def generate(
        self,
        flags: list[RiskFlag],
        value_report: ValueMovementReport,
        property_report: PropertyChecklistReport,
    ) -> RiskScenarioReport:
        """Generate all risk scenarios from combined evidence."""
        scenarios: list[RiskScenario] = []

        scenarios.extend(self._from_flags(flags))
        scenarios.extend(self._from_value_movements(value_report))
        scenarios.extend(self._from_properties(property_report))

        # Deduplicate by title
        seen: set[str] = set()
        unique: list[RiskScenario] = []
        for s in scenarios:
            if s.title not in seen:
                seen.add(s.title)
                unique.append(s)

        summary = self._build_summary(unique)
        return RiskScenarioReport(scenarios=unique, summary=summary)

    # -----------------------------------------------------------------
    # Scenario generators
    # -----------------------------------------------------------------

    def _from_flags(self, flags: list[RiskFlag]) -> list[RiskScenario]:
        """Generate scenarios from heuristic risk flags."""
        scenarios: list[RiskScenario] = []

        for flag in flags:
            category = _CATEGORY_MAP.get(flag.category)
            if not category:
                continue

            fn_label = f"{flag.contract}.{flag.function}" if flag.function else flag.contract

            if flag.category == "access-control":
                scenarios.append(RiskScenario(
                    title=f"Authorization boundary around {fn_label} requires review",
                    category="authorization",
                    risky_assumption=f"Assumes {fn_label} is adequately access-controlled",
                    why_it_matters="If authorization is missing or bypassable, "
                                   "privileged operations could be called by unauthorized parties",
                    affected_functions=[fn_label],
                    severity_hint=_map_severity(flag.severity),
                    manual_validation_steps=[
                        f"Read full source of {flag.function} for inline access checks",
                        "Check if access control is inherited from parent contract",
                        "Verify if function is meant to be publicly callable",
                    ],
                    remediation_themes=[
                        "Add appropriate access control modifier",
                        "Consider two-step process for sensitive operations",
                    ],
                    source_type="heuristic_flag",
                    confidence_basis="heuristic_mapping",
                    evidence_refs=[fn_label, f"flag:{flag.category}:{flag.severity}"],
                ))

            elif flag.category == "external-call":
                scenarios.append(RiskScenario(
                    title=f"External interaction in {fn_label} should be checked for safety",
                    category="external-interaction",
                    risky_assumption=f"Assumes external call targets in {fn_label} are trusted",
                    why_it_matters="External interaction occurs near state transition and "
                                   "should be checked for reentrancy safety",
                    affected_functions=[fn_label],
                    severity_hint=_map_severity(flag.severity),
                    manual_validation_steps=[
                        "Verify call targets are trusted or validated",
                        "Check for checks-effects-interactions pattern",
                        "Look for return value validation",
                        "Verify reentrancy guards are present if needed",
                    ],
                    remediation_themes=[
                        "Apply checks-effects-interactions pattern",
                        "Add reentrancy guard if state is modified",
                    ],
                    source_type="heuristic_flag",
                    confidence_basis="heuristic_mapping",
                    evidence_refs=[fn_label, f"flag:{flag.category}:{flag.severity}"],
                ))

            elif flag.category == "funds-flow":
                scenarios.append(RiskScenario(
                    title=f"Value movement in {fn_label} requires accounting review",
                    category="accounting",
                    risky_assumption=f"Assumes accounting in {fn_label} is correct",
                    why_it_matters="Incorrect accounting near value transfers may "
                                   "affect protocol solvency",
                    affected_functions=[fn_label],
                    severity_hint=_map_severity(flag.severity),
                    manual_validation_steps=[
                        "Verify transfer amounts match internal accounting",
                        "Check reentrancy guards on value-moving functions",
                        "Confirm withdrawal/claim cannot be repeated",
                    ],
                    remediation_themes=[
                        "Ensure accounting updates precede external transfers",
                        "Add reentrancy protection",
                    ],
                    source_type="heuristic_flag",
                    confidence_basis="heuristic_mapping",
                    evidence_refs=[fn_label, f"flag:{flag.category}:{flag.severity}"],
                ))

            elif flag.category == "initialization":
                scenarios.append(RiskScenario(
                    title=f"Initialization/configuration path in {fn_label} should be checked",
                    category="initialization",
                    risky_assumption=f"Assumes initialization in {fn_label} can only succeed once",
                    why_it_matters="Initialization/configuration path should be checked for "
                                   "single-use and role restrictions",
                    affected_functions=[fn_label],
                    severity_hint=_map_severity(flag.severity),
                    manual_validation_steps=[
                        "Verify initializer modifier from OpenZeppelin Initializable",
                        "Check if proxy constructor calls initialize",
                        "Verify initialization sets all critical state",
                    ],
                    remediation_themes=[
                        "Use initializer modifier for single-use enforcement",
                        "Set all critical state in initialization",
                    ],
                    source_type="heuristic_flag",
                    confidence_basis="heuristic_mapping",
                    evidence_refs=[fn_label, f"flag:{flag.category}:{flag.severity}"],
                ))

            elif flag.category == "upgradeability":
                scenarios.append(RiskScenario(
                    title=f"Upgrade path in {fn_label} requires trust boundary review",
                    category="upgradeability",
                    risky_assumption=f"Assumes upgrade authorization in {fn_label} is adequate",
                    why_it_matters="Upgrade functions can replace contract logic entirely — "
                                   "high trust boundary",
                    affected_functions=[fn_label],
                    severity_hint="high",
                    manual_validation_steps=[
                        "Verify upgrade authorization is properly restricted",
                        "Check for storage layout compatibility requirements",
                        "Look for timelock on upgrades",
                    ],
                    remediation_themes=[
                        "Restrict upgrade to authorized roles with timelock",
                        "Ensure storage layout compatibility",
                    ],
                    source_type="heuristic_flag",
                    confidence_basis="heuristic_mapping",
                    evidence_refs=[fn_label, f"flag:{flag.category}:{flag.severity}"],
                ))

            elif flag.category == "oracle-dependency":
                scenarios.append(RiskScenario(
                    title=f"Oracle-dependent calculation in {fn_label} requires validation review",
                    category="oracle",
                    risky_assumption=f"Assumes oracle data in {fn_label} is fresh and accurate",
                    why_it_matters="Oracle-dependent calculation requires validation of "
                                   "freshness and failure handling",
                    affected_functions=[fn_label],
                    severity_hint=_map_severity(flag.severity),
                    manual_validation_steps=[
                        "Add staleness check (updatedAt + heartbeat)",
                        "Add zero/negative price check",
                        "Consider TWAP or multi-oracle for manipulation resistance",
                    ],
                    remediation_themes=[
                        "Add staleness and zero-value validation",
                        "Consider fallback oracle strategy",
                    ],
                    source_type="heuristic_flag",
                    confidence_basis="heuristic_mapping",
                    evidence_refs=[fn_label, f"flag:{flag.category}:{flag.severity}"],
                ))

            elif flag.category == "signature-auth":
                scenarios.append(RiskScenario(
                    title=f"Signature validation in {fn_label} should be checked for replay protection",
                    category="signatures",
                    risky_assumption=f"Assumes signature scheme in {fn_label} includes replay protection",
                    why_it_matters="Signature validation flow should be checked for "
                                   "nonce/deadline/domain separation",
                    affected_functions=[fn_label],
                    severity_hint=_map_severity(flag.severity),
                    manual_validation_steps=[
                        "Verify nonce is incremented after signature use",
                        "Check for deadline/expiry enforcement",
                        "Verify domain separator includes chain ID and contract address",
                    ],
                    remediation_themes=[
                        "Use EIP-712 with domain separator including chain ID",
                        "Include nonce and deadline in signed data",
                    ],
                    source_type="heuristic_flag",
                    confidence_basis="heuristic_mapping",
                    evidence_refs=[fn_label, f"flag:{flag.category}:{flag.severity}"],
                ))

            elif flag.category == "timelock-queue":
                scenarios.append(RiskScenario(
                    title=f"Timelock logic in {fn_label} requires delay enforcement review",
                    category="timelock",
                    risky_assumption=f"Assumes timelock delays in {fn_label} cannot be bypassed",
                    why_it_matters="Timelock delays protect against rushed privileged operations",
                    affected_functions=[fn_label],
                    severity_hint=_map_severity(flag.severity),
                    manual_validation_steps=[
                        "Check minimum delay enforcement",
                        "Verify queue IDs are unique and non-replayable",
                        "Confirm cancel logic is properly authorized",
                    ],
                    remediation_themes=[
                        "Enforce minimum delay",
                        "Ensure queue IDs are unique",
                    ],
                    source_type="heuristic_flag",
                    confidence_basis="heuristic_mapping",
                    evidence_refs=[fn_label, f"flag:{flag.category}:{flag.severity}"],
                ))

        return scenarios

    def _from_value_movements(self, report: ValueMovementReport) -> list[RiskScenario]:
        """Generate scenarios from value movement analysis."""
        scenarios: list[RiskScenario] = []

        # Caller-directed unguarded outflows
        unguarded_caller = [
            e for e in report.edges
            if e.direction == "outflow" and e.caller_influenced and not e.access_controlled
        ]
        if unguarded_caller:
            affected = list({f"{e.contract}.{e.function}" for e in unguarded_caller})
            scenarios.append(RiskScenario(
                title="Caller-directed outflows without access control require review",
                category="authorization",
                risky_assumption="Assumes caller-directed value outflows are intentionally open",
                why_it_matters="Value can be directed to caller-chosen destinations "
                               "without visible authorization checks",
                affected_functions=affected,
                severity_hint="high",
                manual_validation_steps=[
                    "Review authorization on all caller-directed outflows",
                    "Verify withdrawal amounts are bounded by entitlement",
                    "Check for reentrancy protection on outflow paths",
                ],
                remediation_themes=[
                    "Add access control or entitlement checks",
                    "Ensure accounting precedes external transfers",
                ],
                source_type="parsed_fact",
                confidence_basis="regex_match",
                evidence_refs=affected,
            ))

        # External interactions near state transitions
        external_outflows = [
            e for e in report.edges
            if e.direction == "outflow" and e.external_interaction
        ]
        if external_outflows:
            affected = list({f"{e.contract}.{e.function}" for e in external_outflows})
            scenarios.append(RiskScenario(
                title="External interactions near value transfers should be checked for safety",
                category="external-interaction",
                risky_assumption="Assumes external interactions follow checks-effects-interactions",
                why_it_matters="External interaction occurs near state transition and "
                               "should be checked for reentrancy safety",
                affected_functions=affected,
                severity_hint="medium",
                manual_validation_steps=[
                    "Verify checks-effects-interactions pattern is followed",
                    "Check for reentrancy guards where needed",
                ],
                remediation_themes=[
                    "Apply checks-effects-interactions pattern",
                    "Add nonReentrant guard to value-moving functions",
                ],
                source_type="parsed_fact",
                confidence_basis="regex_match",
                evidence_refs=affected,
            ))

        # Unbounded approvals
        approvals = [e for e in report.edges if e.direction == "approval"]
        if approvals:
            affected = list({f"{e.contract}.{e.function}" for e in approvals})
            scenarios.append(RiskScenario(
                title="Token approvals should be reviewed for scope and necessity",
                category="configuration",
                risky_assumption="Assumes token approvals are appropriately scoped",
                why_it_matters="Approvals create delegated spending relationships that "
                               "persist until revoked",
                affected_functions=affected,
                severity_hint="medium",
                manual_validation_steps=[
                    "Verify approved amounts are intentional",
                    "Check if unlimited approvals are necessary",
                    "Verify approved spenders are trusted",
                ],
                remediation_themes=[
                    "Use exact-amount approvals when possible",
                    "Reset approval to zero after use",
                ],
                source_type="parsed_fact",
                confidence_basis="regex_match",
                evidence_refs=affected,
            ))

        return scenarios

    def _from_properties(self, report: PropertyChecklistReport) -> list[RiskScenario]:
        """Generate scenarios from review properties."""
        scenarios: list[RiskScenario] = []

        for prop in report.properties:
            if not prop.related_functions:
                continue

            category = _property_kind_to_category(prop.kind)
            scenarios.append(RiskScenario(
                title=f"Property review: {prop.statement}",
                category=category,
                risky_assumption=f"Assumes property '{prop.statement}' holds across all paths",
                why_it_matters=prop.rationale,
                affected_functions=prop.related_functions[:5],
                severity_hint=_confidence_to_severity(prop.confidence),
                manual_validation_steps=prop.manual_checks,
                remediation_themes=[
                    "Verify property holds for all state-changing paths",
                ],
                source_type=prop.source_type,
                confidence_basis=prop.confidence_basis or "heuristic_mapping",
                evidence_refs=prop.evidence_refs or prop.related_functions[:5],
            ))

        return scenarios

    def _build_summary(self, scenarios: list[RiskScenario]) -> list[str]:
        """Build summary lines."""
        summary: list[str] = []
        summary.append(
            f"Generated {len(scenarios)} risk scenario(s) for manual review."
        )

        high = sum(1 for s in scenarios if s.severity_hint == "high")
        medium = sum(1 for s in scenarios if s.severity_hint == "medium")
        low = sum(1 for s in scenarios if s.severity_hint == "low")

        if high:
            summary.append(f"{high} high-priority scenario(s) requiring review")
        if medium:
            summary.append(f"{medium} medium-priority scenario(s)")
        if low:
            summary.append(f"{low} low-priority scenario(s)")

        summary.append("All scenarios require manual validation.")
        return summary


# -------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------

def _map_severity(sev: str) -> str:
    """Map flag severity to scenario severity hint."""
    if sev in ("critical", "high"):
        return "high"
    if sev == "medium":
        return "medium"
    return "low"


def _confidence_to_severity(confidence: str) -> str:
    """Map property confidence to severity hint."""
    if confidence == "high":
        return "high"
    if confidence == "medium":
        return "medium"
    return "low"


def _property_kind_to_category(kind: str) -> str:
    """Map property kind to scenario category."""
    mapping = {
        "balance": "accounting",
        "supply": "accounting",
        "access": "authorization",
        "ordering": "timelock",
        "initialization": "initialization",
        "configuration": "configuration",
        "oracle": "oracle",
        "signature": "signatures",
        "state": "initialization",
    }
    return mapping.get(kind, "authorization")


# --- Convenience function for pipeline compatibility ---

def generate_risk_scenarios(
    flags: list[RiskFlag],
    value_report: ValueMovementReport,
    property_report: PropertyChecklistReport,
) -> RiskScenarioReport:
    """Top-level entry point matching the old analyze_attack_surface pattern."""
    engine = RiskScenarioEngine()
    return engine.generate(flags, value_report, property_report)
