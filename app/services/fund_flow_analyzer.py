"""Fund flow analyzer — traces where tokens and ETH move through a contract system.

This is the #1 upgrade: real audits are mostly about answering
"where can money move incorrectly?"

For each contract, this module:
1. Identifies entry points (where value comes IN)
2. Identifies exit points (where value goes OUT)
3. Maps the flow edges between them
4. Flags unguarded exits and suspicious patterns
"""

from __future__ import annotations

import re

from app.models.contract_info import ContractInfo
from app.models.function_info import FunctionInfo
from app.models.fund_flow import FundFlowEdge, FundFlowGraph

# --- Deposit/entry patterns ---
_DEPOSIT_NAMES = re.compile(
    r'\b(deposit|stake|supply|addLiquidity|mint|fund|contribute|invest|lock)\b',
    re.IGNORECASE,
)
_PAYABLE_RE = re.compile(r'\bpayable\b')
_RECEIVE_ETH = re.compile(r'\breceive\s*\(\s*\)\s*external\s+payable\b')
_MSG_VALUE = re.compile(r'\bmsg\.value\b')

# --- Withdrawal/exit patterns ---
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

# --- Access control detection (for guarded check) ---
_GUARD_RE = re.compile(
    r'\b(onlyOwner|onlyAdmin|onlyRole|onlyOperator|onlyGuardian|'
    r'onlyGovernance|requiresAuth|auth|onlyMinter|whenNotPaused|nonReentrant)\b',
    re.IGNORECASE,
)
_NONREENTRANT_RE = re.compile(r'\bnonReentrant\b', re.IGNORECASE)

# --- Balance tracking patterns ---
_BALANCE_UPDATE_RE = re.compile(
    r'(?P<mapping>\w+)\s*\[\s*(?P<key>[^\]]+)\]\s*(?P<op>[+\-]?=)\s*(?P<value>[^;]+)',
)
_TOTAL_SUPPLY_RE = re.compile(r'\b(totalSupply|totalAssets|totalDeposits|totalStaked)\b')


def analyze_fund_flows(
    contracts: list[ContractInfo],
    functions: list[FunctionInfo],
) -> FundFlowGraph:
    """Build a complete fund flow graph from parsed contracts and functions."""
    edges: list[FundFlowEdge] = []
    entry_points: list[str] = []
    exit_points: list[str] = []
    internal_moves: list[str] = []
    unguarded_exits: list[str] = []

    for fn in functions:
        fn_label = f"{fn.contract}.{fn.name}"
        source = fn.source
        if not source:
            continue

        is_entry = _is_entry_point(fn)
        is_exit = _is_exit_point(fn)
        is_guarded = _is_guarded(fn)
        is_reentrant_safe = bool(_NONREENTRANT_RE.search(source) or
                                  _NONREENTRANT_RE.search(" ".join(fn.modifiers)))

        if is_entry:
            entry_points.append(fn_label)
        if is_exit:
            exit_points.append(fn_label)
            if not is_guarded:
                unguarded_exits.append(fn_label)

        # Extract transfer edges
        for edge in _extract_transfer_edges(fn, is_guarded, is_reentrant_safe):
            edges.append(edge)

        # Detect internal accounting moves (balance mapping updates without external transfer)
        if _BALANCE_UPDATE_RE.search(source) and not is_entry and not is_exit:
            internal_moves.append(fn_label)

    summary = _build_summary(entry_points, exit_points, unguarded_exits, edges)

    return FundFlowGraph(
        edges=edges,
        entry_points=entry_points,
        exit_points=exit_points,
        internal_moves=internal_moves,
        unguarded_exits=unguarded_exits,
        summary=summary,
    )


def _is_entry_point(fn: FunctionInfo) -> bool:
    """Check if this function is a value entry point."""
    if fn.visibility not in ("public", "external"):
        return False
    source = fn.source
    # Payable functions that accept ETH
    if fn.mutability == "payable" or _MSG_VALUE.search(source):
        return True
    # Named deposit-like functions that call transferFrom (pulling tokens in)
    if _DEPOSIT_NAMES.search(fn.name) and "transferFrom" in source:
        return True
    # Any function that calls transferFrom pulling into address(this)
    if "transferFrom" in source and "address(this)" in source:
        return True
    return False


def _is_exit_point(fn: FunctionInfo) -> bool:
    """Check if this function sends value OUT."""
    if fn.visibility not in ("public", "external"):
        return False
    source = fn.source
    # Named withdrawal functions
    if _WITHDRAW_NAMES.search(fn.name):
        return True
    # Functions with outbound transfers
    if _TRANSFER_RE.search(source) or _ETH_TRANSFER_RE.search(source) or _SEND_RE.search(source):
        # Exclude if it's purely pulling tokens in (transferFrom to self)
        if "transferFrom" in source and "address(this)" in source and not _TRANSFER_RE.search(source):
            return False
        return True
    return False


def _is_guarded(fn: FunctionInfo) -> bool:
    """Check if function has access control."""
    if _GUARD_RE.search(" ".join(fn.modifiers)):
        return True
    if _GUARD_RE.search(fn.source):
        return True
    # Check for require(msg.sender == ...) patterns
    if re.search(r'require\s*\(\s*msg\.sender\s*==', fn.source):
        return True
    if re.search(r'if\s*\(\s*msg\.sender\s*!=', fn.source):
        return True
    return False


def _extract_transfer_edges(
    fn: FunctionInfo,
    is_guarded: bool,
    is_reentrant_safe: bool,
) -> list[FundFlowEdge]:
    """Extract all fund movement edges from a function."""
    edges: list[FundFlowEdge] = []
    source = fn.source
    guard_detail = ""
    if is_guarded:
        guard_match = _GUARD_RE.search(" ".join(fn.modifiers)) or _GUARD_RE.search(source)
        guard_detail = guard_match.group(0) if guard_match else "require check"

    # ERC20 transfer(recipient, amount)
    for m in _TRANSFER_RE.finditer(source):
        edges.append(FundFlowEdge(
            source_contract=fn.contract,
            source_function=fn.name,
            sink_contract="(external)",
            sink_function="",
            file_path=fn.file_path,
            mechanism=f"{m.group('method')}",
            token=m.group("token"),
            sender="address(this)",
            recipient=_clean_param(m.group("recipient")),
            amount_source="see source",
            guarded=is_guarded,
            guard_details=guard_detail,
            reentrancy_safe=is_reentrant_safe,
            evidence=m.group(0).strip(),
        ))

    # ERC20 transferFrom(sender, recipient, amount)
    for m in _TRANSFER_FROM_RE.finditer(source):
        edges.append(FundFlowEdge(
            source_contract="(external)",
            source_function="",
            sink_contract=fn.contract,
            sink_function=fn.name,
            file_path=fn.file_path,
            mechanism=f"{m.group('method')}",
            token=m.group("token"),
            sender=_clean_param(m.group("sender")),
            recipient=_clean_param(m.group("recipient")),
            amount_source=_clean_param(m.group("amount")),
            guarded=is_guarded,
            guard_details=guard_detail,
            reentrancy_safe=is_reentrant_safe,
            evidence=m.group(0).strip(),
        ))

    # ETH via call{value: ...}
    for m in _ETH_TRANSFER_RE.finditer(source):
        edges.append(FundFlowEdge(
            source_contract=fn.contract,
            source_function=fn.name,
            sink_contract="(external)",
            sink_function="",
            file_path=fn.file_path,
            mechanism="call{value}",
            token="ETH",
            sender="address(this)",
            recipient=_clean_param(m.group("recipient")),
            amount_source=_clean_param(m.group("amount")),
            guarded=is_guarded,
            guard_details=guard_detail,
            reentrancy_safe=is_reentrant_safe,
            evidence=m.group(0).strip(),
        ))

    # ETH via .send() or .transfer()
    for m in _SEND_RE.finditer(source):
        # Avoid matching ERC20 .transfer() — those are caught above
        recipient = m.group("recipient")
        if recipient in ("msg.sender", "owner", "recipient", "to", "_to"):
            edges.append(FundFlowEdge(
                source_contract=fn.contract,
                source_function=fn.name,
                sink_contract="(external)",
                sink_function="",
                file_path=fn.file_path,
                mechanism="send/transfer",
                token="ETH",
                sender="address(this)",
                recipient=_clean_param(recipient),
                amount_source=_clean_param(m.group("amount")),
                guarded=is_guarded,
                guard_details=guard_detail,
                reentrancy_safe=is_reentrant_safe,
                evidence=m.group(0).strip(),
            ))

    # Approve (sets up future pull risk)
    for m in _APPROVE_RE.finditer(source):
        edges.append(FundFlowEdge(
            source_contract=fn.contract,
            source_function=fn.name,
            sink_contract="(approved spender)",
            sink_function="",
            file_path=fn.file_path,
            mechanism="approve",
            token=m.group("token"),
            sender="address(this)",
            recipient=_clean_param(m.group("spender")),
            amount_source="allowance",
            guarded=is_guarded,
            guard_details=guard_detail,
            reentrancy_safe=is_reentrant_safe,
            evidence=m.group(0).strip(),
        ))

    return edges


def _clean_param(s: str) -> str:
    """Clean up a captured parameter string."""
    return s.strip().rstrip(",).;")


def _build_summary(
    entry_points: list[str],
    exit_points: list[str],
    unguarded_exits: list[str],
    edges: list[FundFlowEdge],
) -> str:
    """Build a human-readable fund flow summary."""
    lines = []
    lines.append(f"Entry points (value IN): {len(entry_points)}")
    for ep in entry_points:
        lines.append(f"  -> {ep}")
    lines.append(f"Exit points (value OUT): {len(exit_points)}")
    for ep in exit_points:
        marker = " [UNGUARDED]" if ep in unguarded_exits else ""
        lines.append(f"  <- {ep}{marker}")
    lines.append(f"Total flow edges: {len(edges)}")

    if unguarded_exits:
        lines.append(f"\nWARNING: {len(unguarded_exits)} exit point(s) lack access control:")
        for ue in unguarded_exits:
            lines.append(f"  ! {ue}")

    eth_edges = [e for e in edges if e.token == "ETH"]
    if eth_edges:
        lines.append(f"\nETH movement: {len(eth_edges)} edge(s)")

    not_reentrant = [e for e in edges if not e.reentrancy_safe and e.mechanism != "approve"]
    if not_reentrant:
        lines.append(f"\nEdges without reentrancy guard: {len(not_reentrant)}")

    return "\n".join(lines)
