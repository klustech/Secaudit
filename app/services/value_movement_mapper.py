"""Value movement mapper — maps how value enters, moves through, and exits contracts.

Replaces fund_flow_analyzer.py with review-oriented, non-exploitative output.
Every edge describes a value movement for manual review, not an attack path.
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

# --- Access control detection ---
_GUARD_RE = re.compile(
    r'\b(onlyOwner|onlyAdmin|onlyRole|onlyOperator|onlyGuardian|'
    r'onlyGovernance|requiresAuth|auth|onlyMinter|whenNotPaused|nonReentrant)\b',
    re.IGNORECASE,
)

# --- Caller-controlled address patterns ---
_CALLER_CONTROLLED = {"msg.sender", "to", "_to", "recipient", "dest", "target"}


class ValueMovementMapper:
    """Maps value movements through contracts for manual security review."""

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
                ))
            for m in _TRANSFER_FROM_RE.finditer(source):
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
                ))

        # --- Outflow edges ---
        for m in _TRANSFER_RE.finditer(source):
            recipient = _clean(m.group("recipient"))
            caller_inf = recipient in _CALLER_CONTROLLED
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
            ))

        for m in _ETH_TRANSFER_RE.finditer(source):
            recipient = _clean(m.group("recipient"))
            caller_inf = recipient in _CALLER_CONTROLLED
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
            ))

        for m in _SEND_RE.finditer(source):
            recipient = _clean(m.group("recipient"))
            if recipient not in _CALLER_CONTROLLED:
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
            ))

        # --- Approval edges ---
        for m in _APPROVE_RE.finditer(source):
            spender = _clean(m.group("spender"))
            edges.append(ValueMovementEdge(
                contract=fn.contract,
                function=fn.name,
                direction="approval",
                asset_type="erc20",
                mechanism="approve",
                destination_hint=spender,
                caller_influenced=spender in _CALLER_CONTROLLED,
                access_controlled=is_access_controlled,
                external_interaction=True,
                notes=[f"Approval creates delegated spending relationship with {spender}"],
                manual_checks=[
                    "Approval creates delegated spending relationship",
                    "Verify approved amount is intentional (not unlimited unless required)",
                    "Manual verification needed for recipient validation",
                ],
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

        summary.append(f"Value inflow edges: {len(inflows)}")
        summary.append(f"Value outflow edges: {len(outflows)}")
        summary.append(f"Approval edges: {len(approvals)}")

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
    """Check if this function is a value entry point."""
    if fn.visibility not in ("public", "external"):
        return False
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
    """Check if function has access control."""
    if _GUARD_RE.search(" ".join(fn.modifiers)):
        return True
    if _GUARD_RE.search(fn.source):
        return True
    if re.search(r'require\s*\(\s*msg\.sender\s*==', fn.source):
        return True
    if re.search(r'if\s*\(\s*msg\.sender\s*!=', fn.source):
        return True
    return False


def _clean(s: str) -> str:
    """Clean up a captured parameter string."""
    return s.strip().rstrip(",).;")


# --- Convenience function for pipeline compatibility ---

def analyze_value_movements(
    contracts: list[ContractInfo],
    functions: list[FunctionInfo],
) -> ValueMovementReport:
    """Top-level entry point matching the old analyze_fund_flows signature."""
    mapper = ValueMovementMapper()
    return mapper.analyze_functions(functions)
