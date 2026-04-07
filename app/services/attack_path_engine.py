"""Attack path engine — safe, non-exploitative reasoning about risk scenarios.

NOT exploit generation. This answers:
  "IF access control fails here THEN funds may be drained"
  "IF external call is untrusted THEN reentrancy risk"
  "IF accounting mismatch THEN over-withdraw possible"

Each path is a reasoning chain with preconditions, consequences,
and validation steps. The auditor decides if it's real.
"""

from __future__ import annotations

import re
from itertools import count

from app.models.contract_info import ContractInfo
from app.models.function_info import FunctionInfo
from app.models.risk_flag import RiskFlag
from app.models.fund_flow import FundFlowGraph
from app.models.attack_surface import Invariant, InvariantReport
from app.models.attack_path import AttackPath, AttackSurfaceReport

_COUNTER = count(1)


def _next_id() -> str:
    return f"AP-{next(_COUNTER):03d}"


def analyze_attack_surface(
    contracts: list[ContractInfo],
    functions: list[FunctionInfo],
    risk_flags: list[RiskFlag],
    fund_flows: FundFlowGraph,
    invariant_report: InvariantReport,
) -> AttackSurfaceReport:
    """Analyze the full attack surface by combining all analysis layers."""
    paths: list[AttackPath] = []

    paths.extend(_reentrancy_paths(functions, fund_flows))
    paths.extend(_access_bypass_paths(functions, risk_flags, fund_flows))
    paths.extend(_drain_paths(functions, fund_flows))
    paths.extend(_invariant_violation_paths(invariant_report))
    paths.extend(_oracle_manipulation_paths(functions, risk_flags))
    paths.extend(_initialization_paths(functions, risk_flags))
    paths.extend(_replay_paths(functions, risk_flags))
    paths.extend(_dos_paths(functions, risk_flags))

    # Deduplicate by title
    seen_titles: set[str] = set()
    unique_paths: list[AttackPath] = []
    for p in paths:
        if p.title not in seen_titles:
            seen_titles.add(p.title)
            unique_paths.append(p)

    critical = sum(1 for p in unique_paths if p.severity == "critical")
    high = sum(1 for p in unique_paths if p.severity == "high")
    summary = (
        f"Identified {len(unique_paths)} potential attack path(s): "
        f"{critical} critical, {high} high severity. "
        f"All require manual validation."
    )

    return AttackSurfaceReport(
        paths=unique_paths,
        critical_paths=critical,
        high_paths=high,
        summary=summary,
    )


# -------------------------------------------------------------------------
# Individual attack path detectors
# -------------------------------------------------------------------------


def _reentrancy_paths(
    functions: list[FunctionInfo],
    fund_flows: FundFlowGraph,
) -> list[AttackPath]:
    """Detect reentrancy risk: external call before state update."""
    paths: list[AttackPath] = []

    for fn in functions:
        if fn.visibility not in ("public", "external"):
            continue
        source = fn.source
        if not source:
            continue

        has_external_call = (fn.external_calls or
                            re.search(r'\.\s*call\s*[({]', source))
        has_state_write = fn.writes_state
        has_guard = re.search(r'\bnonReentrant\b', " ".join(fn.modifiers) + " " + source)

        if has_external_call and has_state_write and not has_guard:
            # Check if state write comes AFTER external call (rough heuristic)
            call_pos = -1
            for pattern in [r'\.\s*call\s*[({]', r'\.transfer\s*\(', r'\.send\s*\(']:
                m = re.search(pattern, source)
                if m:
                    call_pos = max(call_pos, m.start())

            write_pos = -1
            for m in re.finditer(r'(\w+\s*=\s*[^=]|\w+\s*[+\-]=)', source):
                if m.start() > call_pos and call_pos >= 0:
                    write_pos = m.start()
                    break

            if call_pos >= 0 and write_pos > call_pos:
                severity = "critical"
                why = "External call occurs BEFORE state update — classic reentrancy pattern"
            elif call_pos >= 0:
                severity = "high"
                why = "External call without reentrancy guard — ordering unclear"
            else:
                continue

            mitigations = []
            if re.search(r'\bReentrancyGuard\b', source):
                mitigations.append("ReentrancyGuard inherited but nonReentrant not applied to this function")

            paths.append(AttackPath(
                id=_next_id(),
                title=f"Reentrancy risk in {fn.contract}.{fn.name}",
                severity=severity,
                preconditions=[
                    "Attacker deploys contract with fallback/receive that re-calls this function",
                    f"No reentrancy guard on {fn.name}",
                ],
                affected_functions=[f"{fn.contract}.{fn.name}"],
                affected_contracts=[fn.contract],
                risk_category="reentrancy",
                consequence="State may be inconsistent during re-entrant call, potentially allowing double-spend or over-withdrawal",
                likelihood="requires-validation",
                evidence=[why],
                why_concerning=why,
                what_prevents_it="; ".join(mitigations) if mitigations else "No mitigations found",
                validation_steps=[
                    "Trace exact order: external call vs state update",
                    "Check if nonReentrant modifier should be added",
                    "Verify checks-effects-interactions pattern",
                    "Test with a re-entrant callback contract",
                ],
            ))

    return paths


def _access_bypass_paths(
    functions: list[FunctionInfo],
    risk_flags: list[RiskFlag],
    fund_flows: FundFlowGraph,
) -> list[AttackPath]:
    """Detect paths where access control might be bypassable."""
    paths: list[AttackPath] = []

    ac_flags = [f for f in risk_flags if f.category == "access-control"
                and f.severity in ("high", "critical")]

    for flag in ac_flags:
        fn = _find_fn(functions, flag.contract, flag.function)
        if not fn:
            continue

        # Check what this function can do
        consequences = []
        if fn.token_actions:
            consequences.append(f"move tokens via {fn.token_actions}")
        if re.search(r'\b(owner|admin|operator)\s*=', fn.source):
            consequences.append("change privileged roles")
        if re.search(r'\b(paused|pause)\s*=', fn.source):
            consequences.append("toggle pause state")
        if fn.writes_state:
            consequences.append("modify contract state")

        if not consequences:
            continue

        paths.append(AttackPath(
            id=_next_id(),
            title=f"Access bypass in {fn.contract}.{fn.name}",
            severity="high" if fn.token_actions else "medium",
            preconditions=[
                f"No visible access control on {fn.name}",
                "Function is externally callable",
            ],
            affected_functions=[f"{fn.contract}.{fn.name}"],
            affected_contracts=[fn.contract],
            risk_category="access-bypass",
            consequence=f"Any caller could: {', '.join(consequences)}",
            likelihood="requires-validation",
            evidence=[flag.evidence],
            why_concerning=f"Unprotected function can {consequences[0]}",
            what_prevents_it="Check for inline require() or if() access checks",
            validation_steps=[
                f"Read full source of {fn.name} for inline access checks",
                "Check if access control is inherited from parent contract",
                "Verify if function is meant to be public",
                "Test calling function from unauthorized address",
            ],
            related_flags=[f"{flag.category}:{flag.function}"],
        ))

    return paths


def _drain_paths(
    functions: list[FunctionInfo],
    fund_flows: FundFlowGraph,
) -> list[AttackPath]:
    """Detect potential fund drain scenarios."""
    paths: list[AttackPath] = []

    for ue in fund_flows.unguarded_exits:
        contract, fn_name = ue.split(".", 1)
        fn = _find_fn(functions, contract, fn_name)
        if not fn:
            continue

        # Find what tokens/ETH this can send
        relevant_edges = [e for e in fund_flows.edges
                          if e.source_function == fn_name
                          and e.source_contract == contract
                          and not e.guarded]

        if not relevant_edges:
            continue

        mechanisms = list({e.mechanism for e in relevant_edges})
        tokens = list({e.token for e in relevant_edges if e.token})
        recipients = list({e.recipient for e in relevant_edges})

        # Check if recipient is controllable
        has_arbitrary_recipient = any(
            r in ("msg.sender", "to", "_to", "recipient", "dest", "target")
            for r in recipients
        )

        if has_arbitrary_recipient:
            severity = "critical"
        else:
            severity = "high"

        paths.append(AttackPath(
            id=_next_id(),
            title=f"Potential fund drain via {contract}.{fn_name}",
            severity=severity,
            preconditions=[
                f"No access control on {fn_name}",
                f"Function sends {tokens or 'value'} via {mechanisms}",
            ],
            affected_functions=[ue],
            affected_contracts=[contract],
            risk_category="drain",
            consequence=f"Attacker could drain {tokens or ['funds']} from contract",
            likelihood="requires-validation",
            evidence=[e.evidence for e in relevant_edges[:3]],
            why_concerning=f"Unguarded exit point sends value to {'caller-controlled' if has_arbitrary_recipient else 'fixed'} address",
            what_prevents_it="Check for inline access control or amount limitations",
            validation_steps=[
                f"Verify {fn_name} has adequate access control",
                "Check if withdrawal amount is properly bounded",
                "Verify balance accounting prevents over-withdrawal",
                "Check for flash loan attack vectors",
            ],
        ))

    return paths


def _invariant_violation_paths(
    invariant_report: InvariantReport,
) -> list[AttackPath]:
    """Generate attack paths from threatened invariants."""
    paths: list[AttackPath] = []

    for inv in invariant_report.invariants:
        if not inv.threatened_by:
            continue

        if inv.kind == "balance":
            severity = "high"
            category = "drain"
            consequence = f"Breaking '{inv.description}' could allow over-withdrawal or accounting errors"
        elif inv.kind == "supply":
            severity = "high"
            category = "manipulation"
            consequence = f"Breaking '{inv.description}' could allow token inflation or share price manipulation"
        elif inv.kind == "access":
            severity = "high"
            category = "access-bypass"
            consequence = f"Breaking '{inv.description}' could allow unauthorized privileged operations"
        elif inv.kind == "ordering":
            severity = "medium"
            category = "replay"
            consequence = f"Breaking '{inv.description}' could allow replay attacks or deadline bypass"
        else:
            severity = "medium"
            category = "manipulation"
            consequence = f"Breaking '{inv.description}' could have unexpected consequences"

        paths.append(AttackPath(
            id=_next_id(),
            title=f"Invariant threat: {inv.description}",
            severity=severity,
            preconditions=[f"Invariant '{inv.description}' can be violated"],
            affected_functions=inv.threatened_by[:5],
            affected_contracts=[inv.contract],
            risk_category=category,
            consequence=consequence,
            likelihood="requires-validation",
            evidence=[inv.evidence],
            why_concerning=f"Functions {inv.threatened_by[:3]} may violate this invariant",
            what_prevents_it="See manual checks",
            validation_steps=inv.manual_checks,
        ))

    return paths


def _oracle_manipulation_paths(
    functions: list[FunctionInfo],
    risk_flags: list[RiskFlag],
) -> list[AttackPath]:
    """Detect oracle manipulation risks."""
    paths: list[AttackPath] = []

    oracle_flags = [f for f in risk_flags if f.category == "oracle-dependency"]
    for flag in oracle_flags:
        fn = _find_fn(functions, flag.contract, flag.function)
        if not fn:
            continue

        has_staleness = re.search(r'(updatedAt|timestamp|stale|heartbeat)', fn.source, re.IGNORECASE)
        has_zero_check = re.search(r'(price\s*[><=]\s*0|require.*price)', fn.source)

        mitigations = []
        if has_staleness:
            mitigations.append("Staleness check found")
        if has_zero_check:
            mitigations.append("Price validation found")

        if not mitigations:
            paths.append(AttackPath(
                id=_next_id(),
                title=f"Oracle manipulation risk in {fn.contract}.{fn.name}",
                severity="high",
                preconditions=[
                    "Oracle returns stale or manipulated price",
                    "No staleness or zero-price check found",
                ],
                affected_functions=[f"{fn.contract}.{fn.name}"],
                affected_contracts=[fn.contract],
                risk_category="manipulation",
                consequence="Incorrect pricing could allow profitable trades against the protocol",
                likelihood="requires-validation",
                evidence=[flag.evidence],
                why_concerning="Oracle data used without apparent validation",
                what_prevents_it="No mitigations detected — needs review",
                validation_steps=[
                    "Add staleness check (updatedAt + heartbeat)",
                    "Add zero/negative price check",
                    "Consider TWAP or multi-oracle for manipulation resistance",
                    "Check if flash loan can manipulate spot price oracle",
                ],
            ))

    return paths


def _initialization_paths(
    functions: list[FunctionInfo],
    risk_flags: list[RiskFlag],
) -> list[AttackPath]:
    """Detect initialization attack risks."""
    paths: list[AttackPath] = []

    init_flags = [f for f in risk_flags if f.category == "initialization"]
    for flag in init_flags:
        fn = _find_fn(functions, flag.contract, flag.function)
        if not fn:
            continue

        has_initializer = re.search(r'\binitializer\b', fn.source)
        has_guard = re.search(r'\b(initialized|_initialized)\b', fn.source)

        if not has_initializer and not has_guard:
            paths.append(AttackPath(
                id=_next_id(),
                title=f"Unprotected initializer in {fn.contract}.{fn.name}",
                severity="critical",
                preconditions=[
                    f"{fn.name} can be called by anyone",
                    "No initializer modifier or guard boolean detected",
                ],
                affected_functions=[f"{fn.contract}.{fn.name}"],
                affected_contracts=[fn.contract],
                risk_category="access-bypass",
                consequence="Attacker could re-initialize contract with their own parameters, taking ownership",
                likelihood="requires-validation",
                evidence=[flag.evidence],
                why_concerning="Initialization without single-use guard can be called multiple times",
                what_prevents_it="Check for initializer modifier in parent contract",
                validation_steps=[
                    "Verify initializer modifier from OpenZeppelin Initializable",
                    "Check if proxy constructor calls initialize",
                    "Test calling initialize on deployed proxy",
                ],
            ))

    return paths


def _replay_paths(
    functions: list[FunctionInfo],
    risk_flags: list[RiskFlag],
) -> list[AttackPath]:
    """Detect signature/action replay risks."""
    paths: list[AttackPath] = []

    sig_flags = [f for f in risk_flags if f.category == "signature-auth"]
    for flag in sig_flags:
        fn = _find_fn(functions, flag.contract, flag.function)
        if not fn:
            continue

        has_nonce = re.search(r'\bnonce\b', fn.source, re.IGNORECASE)
        has_deadline = re.search(r'\b(deadline|expiry)\b', fn.source, re.IGNORECASE)
        has_chain_id = re.search(r'\bchainId|chain_id|block\.chainid\b', fn.source, re.IGNORECASE)

        missing = []
        if not has_nonce:
            missing.append("nonce (same signature reusable)")
        if not has_deadline:
            missing.append("deadline (signature never expires)")
        if not has_chain_id:
            missing.append("chain ID (cross-chain replay possible)")

        if missing:
            paths.append(AttackPath(
                id=_next_id(),
                title=f"Signature replay risk in {fn.contract}.{fn.name}",
                severity="high",
                preconditions=[
                    f"Missing replay protections: {', '.join(missing)}",
                ],
                affected_functions=[f"{fn.contract}.{fn.name}"],
                affected_contracts=[fn.contract],
                risk_category="replay",
                consequence="Signed message could be replayed to execute action multiple times or on other chains",
                likelihood="requires-validation",
                evidence=[flag.evidence],
                why_concerning=f"Missing: {', '.join(missing)}",
                what_prevents_it="Check for EIP-712 domain separator with chain ID",
                validation_steps=[
                    "Verify nonce is incremented after signature use",
                    "Check for deadline/expiry enforcement",
                    "Verify domain separator includes chain ID and contract address",
                    "Test same signature on different chain/fork",
                ],
            ))

    return paths


def _dos_paths(
    functions: list[FunctionInfo],
    risk_flags: list[RiskFlag],
) -> list[AttackPath]:
    """Detect denial-of-service risks."""
    paths: list[AttackPath] = []

    for fn in functions:
        if fn.visibility not in ("public", "external"):
            continue
        source = fn.source

        # Unbounded loop over user-controlled array
        has_loop = re.search(r'\bfor\s*\(', source)
        has_array_length = re.search(r'\.length\b', source)
        has_external_in_loop = False

        if has_loop and has_array_length:
            # Rough check: external call inside a for loop
            loop_match = re.search(r'for\s*\([^)]*\)\s*\{', source)
            if loop_match:
                loop_body_start = source.find("{", loop_match.start())
                if loop_body_start >= 0:
                    # Simple extraction
                    depth = 0
                    end = loop_body_start
                    for i in range(loop_body_start, len(source)):
                        if source[i] == "{":
                            depth += 1
                        elif source[i] == "}":
                            depth -= 1
                            if depth == 0:
                                end = i
                                break
                    loop_body = source[loop_body_start:end]
                    if re.search(r'\.\s*call\s*[({]|\.transfer\s*\(|\.send\s*\(', loop_body):
                        has_external_in_loop = True

            if has_external_in_loop:
                paths.append(AttackPath(
                    id=_next_id(),
                    title=f"DoS via unbounded loop in {fn.contract}.{fn.name}",
                    severity="medium",
                    preconditions=[
                        "Array iterated in loop is user-growable or unbounded",
                        "External call inside loop can fail/revert",
                    ],
                    affected_functions=[f"{fn.contract}.{fn.name}"],
                    affected_contracts=[fn.contract],
                    risk_category="dos",
                    consequence="If one external call fails, entire transaction reverts — attacker can block the function",
                    likelihood="requires-validation",
                    evidence=[f"Loop with external call in {fn.name}"],
                    why_concerning="Unbounded external calls in loop can be blocked by a single reverting recipient",
                    what_prevents_it="Check if array length is bounded or if pull-over-push pattern is used",
                    validation_steps=[
                        "Verify array length is bounded",
                        "Check if external call failure is handled (try/catch)",
                        "Consider pull-over-push pattern for distributions",
                        "Test with reverting recipient contract",
                    ],
                ))

    return paths


# -------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------

def _find_fn(
    functions: list[FunctionInfo], contract: str, name: str
) -> FunctionInfo | None:
    """Find a function by contract and name."""
    for fn in functions:
        if fn.contract == contract and fn.name == name:
            return fn
    return None
