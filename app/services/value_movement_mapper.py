"""Value movement mapper — maps how value enters, moves through, and exits contracts.

Replaces fund_flow_analyzer.py with review-oriented, non-exploitative output.
Every edge describes a value movement for manual review, not an attack path.

False-positive reduction strategy:
- Prefer FunctionInfo metadata (token_actions, external_calls) over raw regex
- Split "high confidence" (metadata-backed) from "possible" (regex-only)
- Detect inherited and inline guards more thoroughly
- Skip internal/private helpers as direct entry/exit points
"""

from __future__ import annotations

import re

from app.models.contract_info import ContractInfo
from app.models.function_info import FunctionInfo
from app.models.value_movement import ValueMovementEdge, ValueMovementReport

# --- Entry point patterns ---
_DEPOSIT_NAMES = re.compile(
    r'\b(deposit|stake|supply|addLiquidity|mint|fund|contribute|invest|lock)\b',
    re.IGNORECASE,
)
_PAYABLE_RE = re.compile(r'\bpayable\b')
_RECEIVE_ETH = re.compile(r'\breceive\s*\(\s*\)\s*external\s+payable\b')
_MSG_VALUE = re.compile(r'\bmsg\.value\b')
_FALLBACK_RE = re.compile(r'\bfallback\s*\(')

# --- Exit point patterns ---
_WITHDRAW_NAMES = re.compile(
    r'\b(withdraw|redeem|claim|unstake|removeLiquidity|sweep|rescue|'
    r'harvest|collect|emergencyWithdraw|exit)\b',
    re.IGNORECASE,
)

# --- Transfer mechanism detection ---
_TRANSFER_RE = re.compile(
    r'(?P<token>\w+)\s*\.\s*(?P<method>transfer|safeTransfer)\s*\(\s*(?P<recipient>[^,)]+)',
)
_TRANSFER_FROM_RE = re.compile(
    r'(?P<token>\w+)\s*\.\s*(?P<method>transferFrom|safeTransferFrom)\s*\('
    r'\s*(?P<sender>[^,]+)\s*,\s*(?P<recipient>[^,]+)\s*,\s*(?P<amount>[^)]+)',
)
_ETH_TRANSFER_RE = re.compile(
    r'(?P<recipient>\w+)\s*\.\s*call\s*\{\s*value\s*:\s*(?P<amount>[^}]+)\}',
)
_SEND_RE = re.compile(r'(?P<recipient>\w+)\s*\.\s*(?:send|transfer)\s*\(\s*(?P<amount>[^)]+)\)')
_APPROVE_RE = re.compile(
    r'(?P<token>\w+)\s*\.\s*approve\s*\(\s*(?P<spender>[^,)]+)',
)

# --- Non-standard transfer wrappers (common in DeFi) ---
_WRAPPER_TRANSFER_RE = re.compile(
    r'\b(_safeTransfer|_transfer|_sendETH|_sendValue|_pushToken|_pullToken|'
    r'_safeTokenTransfer|_doTransferOut|_doTransferIn)\b',
)

# --- Access control detection (expanded for inherited guards) ---
_GUARD_RE = re.compile(
    r'\b(onlyOwner|onlyAdmin|onlyRole|onlyOperator|onlyGuardian|'
    r'onlyGovernance|requiresAuth|auth|onlyMinter|whenNotPaused|nonReentrant|'
    r'onlyVault|onlyStrategy|onlyKeeper|onlyManager|onlyController|'
    r'onlyWhitelisted|onlyAuthorized|onlyMultisig)\b',
    re.IGNORECASE,
)

# --- Inline access control patterns ---
_INLINE_GUARD_RE = re.compile(
    r'require\s*\(\s*(?:msg\.sender\s*==|hasRole|_checkRole|isAuthorized|'
    r'_onlyOwner|_checkOwner|_requireAuth)',
)
_IF_GUARD_RE = re.compile(
    r'if\s*\(\s*(?:msg\.sender\s*!=|!hasRole|!isAuthorized)',
)

# --- Caller-controlled address patterns ---
_CALLER_CONTROLLED = {"msg.sender", "to", "_to", "recipient", "dest", "target",
                      "receiver", "_receiver", "beneficiary", "_beneficiary"}


class ValueMovementMapper:
    """Maps value movements through contracts for manual security review."""

    def __init__(self, contracts: list[ContractInfo] | None = None):
        self._contract_map: dict[str, ContractInfo] = {}
        if contracts:
            for c in contracts:
                self._contract_map[c.name] = c

    def analyze_functions(
        self,
        functions: list[FunctionInfo],
    ) -> ValueMovementReport:
        """Build a complete value movement report from parsed functions."""
        all_edges: list[ValueMovementEdge] = []
        for fn in functions:
            if not fn.source:
                continue
            all_edges.extend(self.detect_edges(fn))

        summary = self.summarize(all_edges)
        return ValueMovementReport(edges=all_edges, summary=summary)

    def detect_edges(self, fn: FunctionInfo) -> list[ValueMovementEdge]:
        """Detect all value movement edges in a single function."""
        edges: list[ValueMovementEdge] = []
        source = fn.source
        is_access_controlled = _is_guarded(fn)
        has_external = bool(fn.external_calls or re.search(r'\.\s*call\s*[({]', source))

        # --- Inflow edges ---
        if _is_entry_point(fn):
            direction = "inflow"
            if fn.mutability == "payable" or _MSG_VALUE.search(source):
                # Use metadata to determine confidence
                is_metadata_backed = fn.mutability == "payable"
                edges.append(ValueMovementEdge(
                    contract=fn.contract,
                    function=fn.name,
                    direction=direction,
                    asset_type="eth",
                    mechanism="payable/msg.value",
                    source_hint="caller",
                    destination_hint="contract",
                    caller_influenced=True,
                    access_controlled=is_access_controlled,
                    external_interaction=False,
                    notes=["ETH received via payable function"],
                    manual_checks=[
                        "Verify accounting is updated for received ETH",
                    ],
                    confidence="high" if is_metadata_backed else "possible",
                    source_type="parsed_fact",
                    confidence_basis="mutability_keyword" if is_metadata_backed else "regex_match",
                    evidence_refs=[f"{fn.contract}.{fn.name}"],
                ))
            for m in _TRANSFER_FROM_RE.finditer(source):
                # High confidence if token_actions confirms transferFrom
                has_metadata = "transferFrom" in fn.token_actions or "safeTransferFrom" in fn.token_actions
                edges.append(ValueMovementEdge(
                    contract=fn.contract,
                    function=fn.name,
                    direction=direction,
                    asset_type="erc20",
                    mechanism=m.group("method"),
                    source_hint=_clean(m.group("sender")),
                    destination_hint=_clean(m.group("recipient")),
                    caller_influenced=True,
                    access_controlled=is_access_controlled,
                    external_interaction=True,
                    notes=[f"Token pulled via {m.group('method')}"],
                    manual_checks=[
                        "Verify amount credited matches amount transferred",
                    ],
                    confidence="high" if has_metadata else "possible",
                    source_type="parsed_fact",
                    confidence_basis="token_actions" if has_metadata else "regex_match",
                    evidence_refs=[f"{fn.contract}.{fn.name}", m.group("method")],
                ))

        # --- Outflow edges ---
        for m in _TRANSFER_RE.finditer(source):
            recipient = _clean(m.group("recipient"))
            caller_inf = _is_caller_controlled(recipient)
            # High confidence if metadata confirms transfer action
            has_metadata = "transfer" in fn.token_actions or "safeTransfer" in fn.token_actions
            checks = ["Verify state/accounting is updated before external transfer"]
            if caller_inf:
                checks.insert(0, "Verify recipient constraints are intentional")
                checks.append("Verify caller cannot withdraw beyond entitled amount")
            edges.append(ValueMovementEdge(
                contract=fn.contract,
                function=fn.name,
                direction="outflow",
                asset_type="erc20",
                mechanism=m.group("method"),
                destination_hint=recipient,
                caller_influenced=caller_inf,
                access_controlled=is_access_controlled,
                external_interaction=True,
                notes=[f"Token sent via {m.group('method')} to {recipient}"],
                manual_checks=checks,
                confidence="high" if has_metadata else "possible",
                source_type="parsed_fact",
                confidence_basis="token_actions" if has_metadata else "regex_match",
                evidence_refs=[f"{fn.contract}.{fn.name}", m.group("method")],
            ))

        for m in _ETH_TRANSFER_RE.finditer(source):
            recipient = _clean(m.group("recipient"))
            caller_inf = _is_caller_controlled(recipient)
            # High confidence if external_calls confirms call pattern
            has_metadata = any(".call{" in c or "call{value" in c for c in fn.external_calls)
            checks = [
                "Verify state/accounting is updated before external transfer",
                "Verify checks-effects-interactions pattern is followed",
            ]
            if caller_inf:
                checks.insert(0, "Verify recipient constraints are intentional")
            edges.append(ValueMovementEdge(
                contract=fn.contract,
                function=fn.name,
                direction="outflow",
                asset_type="eth",
                mechanism="call{value}",
                destination_hint=recipient,
                caller_influenced=caller_inf,
                access_controlled=is_access_controlled,
                external_interaction=True,
                notes=[f"ETH sent via call{{value}} to {recipient}"],
                manual_checks=checks,
                confidence="high" if has_metadata else "possible",
                source_type="parsed_fact",
                confidence_basis="external_calls" if has_metadata else "regex_match",
                evidence_refs=[f"{fn.contract}.{fn.name}", "call{value}"],
            ))

        for m in _SEND_RE.finditer(source):
            recipient = _clean(m.group("recipient"))
            if not _is_caller_controlled(recipient):
                # Still detect non-caller-directed sends as "possible" edges
                edges.append(ValueMovementEdge(
                    contract=fn.contract,
                    function=fn.name,
                    direction="outflow",
                    asset_type="eth",
                    mechanism="send/transfer",
                    destination_hint=recipient,
                    caller_influenced=False,
                    access_controlled=is_access_controlled,
                    external_interaction=True,
                    notes=[f"ETH sent via send/transfer to {recipient}"],
                    manual_checks=[
                        "Verify state/accounting is updated before external transfer",
                    ],
                    confidence="possible",
                    source_type="parsed_fact",
                    confidence_basis="regex_match",
                    evidence_refs=[f"{fn.contract}.{fn.name}", "send/transfer"],
                ))
                continue
            edges.append(ValueMovementEdge(
                contract=fn.contract,
                function=fn.name,
                direction="outflow",
                asset_type="eth",
                mechanism="send/transfer",
                destination_hint=recipient,
                caller_influenced=True,
                access_controlled=is_access_controlled,
                external_interaction=True,
                notes=[f"ETH sent via send/transfer to {recipient}"],
                manual_checks=[
                    "Verify recipient constraints are intentional",
                    "Verify state/accounting is updated before external transfer",
                ],
                confidence="high",
                source_type="parsed_fact",
                confidence_basis="regex_match",
                evidence_refs=[f"{fn.contract}.{fn.name}", "send/transfer"],
            ))

        # --- Wrapper transfer detection (possible confidence) ---
        for m in _WRAPPER_TRANSFER_RE.finditer(source):
            wrapper_name = m.group(0)
            # Only flag if not already detected via standard patterns
            if not edges or not any(
                wrapper_name.replace("_", "") in (e.mechanism or "") for e in edges
            ):
                edges.append(ValueMovementEdge(
                    contract=fn.contract,
                    function=fn.name,
                    direction="outflow",
                    asset_type="unknown",
                    mechanism=wrapper_name,
                    caller_influenced=False,
                    access_controlled=is_access_controlled,
                    external_interaction=True,
                    notes=[f"Value transfer via wrapper function {wrapper_name}"],
                    manual_checks=[
                        f"Inspect implementation of {wrapper_name} for actual transfer mechanism",
                        "Verify state/accounting is updated before wrapper call",
                    ],
                    confidence="possible",
                    source_type="heuristic_flag",
                    confidence_basis="regex_match",
                    evidence_refs=[f"{fn.contract}.{fn.name}", wrapper_name],
                ))

        # --- Approval edges ---
        for m in _APPROVE_RE.finditer(source):
            spender = _clean(m.group("spender"))
            has_metadata = "approve" in fn.token_actions
            edges.append(ValueMovementEdge(
                contract=fn.contract,
                function=fn.name,
                direction="approval",
                asset_type="erc20",
                mechanism="approve",
                destination_hint=spender,
                caller_influenced=_is_caller_controlled(spender),
                access_controlled=is_access_controlled,
                external_interaction=True,
                notes=[f"Approval creates delegated spending relationship with {spender}"],
                manual_checks=[
                    "Approval creates delegated spending relationship",
                    "Verify approved amount is intentional (not unlimited unless required)",
                    "Manual verification needed for recipient validation",
                ],
                confidence="high" if has_metadata else "possible",
                source_type="parsed_fact",
                confidence_basis="token_actions" if has_metadata else "regex_match",
                evidence_refs=[f"{fn.contract}.{fn.name}", "approve"],
            ))

        # Tag access-control review notes
        for edge in edges:
            if edge.direction == "outflow" and edge.caller_influenced and not edge.access_controlled:
                edge.manual_checks.append(
                    "Caller-directed outflow requires authorization review"
                )
            if edge.external_interaction and edge.direction == "outflow":
                if "checks-effects-interactions" not in " ".join(edge.manual_checks):
                    edge.manual_checks.append(
                        "External value transfer should be checked for checks-effects-interactions"
                    )

        return edges

    def summarize(self, edges: list[ValueMovementEdge]) -> list[str]:
        """Build human-readable summary lines."""
        summary: list[str] = []
        inflows = [e for e in edges if e.direction == "inflow"]
        outflows = [e for e in edges if e.direction == "outflow"]
        approvals = [e for e in edges if e.direction == "approval"]

        high_conf = [e for e in edges if e.confidence == "high"]
        possible = [e for e in edges if e.confidence == "possible"]

        summary.append(f"Value inflow edges: {len(inflows)}")
        summary.append(f"Value outflow edges: {len(outflows)}")
        summary.append(f"Approval edges: {len(approvals)}")

        if high_conf:
            summary.append(f"{len(high_conf)} high-confidence edge(s)")
        if possible:
            summary.append(f"{len(possible)} possible edge(s) — may need manual verification")

        caller_directed = [e for e in outflows if e.caller_influenced]
        if caller_directed:
            summary.append(
                f"{len(caller_directed)} outflow(s) with caller-influenced destinations"
            )

        unguarded_outflows = [e for e in outflows if not e.access_controlled]
        if unguarded_outflows:
            summary.append(
                f"{len(unguarded_outflows)} outflow(s) without visible access control — review recommended"
            )

        return summary


# -------------------------------------------------------------------------
# Module-level helpers
# -------------------------------------------------------------------------

def _is_entry_point(fn: FunctionInfo) -> bool:
    """Check if this function is a value entry point.

    Uses metadata first, then falls back to regex.
    """
    if fn.visibility not in ("public", "external"):
        return False

    # Metadata-based detection: check token_actions for inflow patterns
    if fn.token_actions:
        inflow_actions = {"transferFrom", "safeTransferFrom"}
        if inflow_actions & set(fn.token_actions):
            return True

    source = fn.source
    if fn.mutability == "payable" or _MSG_VALUE.search(source):
        return True
    if _DEPOSIT_NAMES.search(fn.name) and "transferFrom" in source:
        return True
    if "transferFrom" in source and "address(this)" in source:
        return True
    if _RECEIVE_ETH.search(source) or _FALLBACK_RE.search(source):
        return True
    return False


def _is_guarded(fn: FunctionInfo) -> bool:
    """Check if function has access control, including inherited guards."""
    # Check modifiers (includes inherited modifiers)
    if _GUARD_RE.search(" ".join(fn.modifiers)):
        return True
    # Check source for inline guard patterns
    if _GUARD_RE.search(fn.source):
        return True
    # Check for require(msg.sender == ...) patterns
    if _INLINE_GUARD_RE.search(fn.source):
        return True
    # Check for if (msg.sender != ...) revert patterns
    if _IF_GUARD_RE.search(fn.source):
        return True
    # Legacy patterns
    if re.search(r'require\s*\(\s*msg\.sender\s*==', fn.source):
        return True
    if re.search(r'if\s*\(\s*msg\.sender\s*!=', fn.source):
        return True
    return False


def _is_caller_controlled(param: str) -> bool:
    """Check if a parameter is caller-controlled."""
    return param in _CALLER_CONTROLLED


def _clean(s: str) -> str:
    """Clean up a captured parameter string."""
    return s.strip().rstrip(",).;")


# --- Convenience function for pipeline compatibility ---

def analyze_value_movements(
    contracts: list[ContractInfo],
    functions: list[FunctionInfo],
) -> ValueMovementReport:
    """Top-level entry point matching the old analyze_fund_flows signature."""
    mapper = ValueMovementMapper(contracts=contracts)
    return mapper.analyze_functions(functions)
