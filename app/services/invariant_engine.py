"""Invariant engine — infers expected properties for contracts and checks which
functions might violate them.

Real auditors think in invariants:
  "total deposits should always equal sum of balances"
  "only owner should be able to withdraw"
  "share price should never decrease"

This engine infers invariants from contract structure, then checks which
functions could threaten each one.
"""

from __future__ import annotations

import re

from app.models.contract_info import ContractInfo
from app.models.function_info import FunctionInfo
from app.models.attack_surface import Invariant, InvariantReport
from app.models.risk_flag import RiskFlag

# --- Patterns for invariant inference ---

_BALANCE_MAPPING = re.compile(
    r'mapping\s*\([^)]*\)\s*(?:public\s+)?(?P<name>\w*[Bb]alance\w*)',
)
_TOTAL_TRACKER = re.compile(
    r'(?:uint\d*\s+(?:public\s+)?)?(?P<name>total\w+)',
    re.IGNORECASE,
)
_OWNER_VAR = re.compile(r'\b(?:address\s+(?:public\s+)?)?(?P<name>owner|admin|governance)\b')
_PAUSED_VAR = re.compile(r'\b(?:bool\s+(?:public\s+)?)?(?P<name>paused|isPaused)\b')
_SUPPLY_VAR = re.compile(r'\btotalSupply\b')
_SHARE_PRICE = re.compile(r'\b(sharePrice|exchangeRate|pricePerShare|convertToAssets)\b')
_ALLOWANCE_PATTERN = re.compile(r'\ballowance\b')
_NONCE_PATTERN = re.compile(r'\bnonce\b', re.IGNORECASE)
_DEADLINE_PATTERN = re.compile(r'\b(deadline|expiry|validUntil)\b', re.IGNORECASE)
_INITIALIZED_PATTERN = re.compile(r'\b(initialized|_initialized)\b')


def infer_invariants(
    contracts: list[ContractInfo],
    functions: list[FunctionInfo],
    risk_flags: list[RiskFlag],
) -> InvariantReport:
    """Infer invariants from contract structure and check threats."""
    all_invariants: list[Invariant] = []

    for contract in contracts:
        if contract.kind in ("interface", "library"):
            continue

        contract_fns = [f for f in functions if f.contract == contract.name]
        contract_flags = [f for f in risk_flags if f.contract == contract.name]
        contract_source = " ".join(f.source for f in contract_fns)

        # 1. Balance conservation invariants
        all_invariants.extend(
            _infer_balance_invariants(contract, contract_fns, contract_source)
        )

        # 2. Access control invariants
        all_invariants.extend(
            _infer_access_invariants(contract, contract_fns, contract_flags)
        )

        # 3. State ordering invariants
        all_invariants.extend(
            _infer_state_invariants(contract, contract_fns, contract_source)
        )

        # 4. Supply invariants
        all_invariants.extend(
            _infer_supply_invariants(contract, contract_fns, contract_source)
        )

        # 5. Initialization invariants
        all_invariants.extend(
            _infer_init_invariants(contract, contract_fns, contract_source)
        )

    broken_count = sum(1 for inv in all_invariants if inv.threatened_by)
    summary = (
        f"Inferred {len(all_invariants)} invariant(s) across "
        f"{len(contracts)} contract(s). "
        f"{broken_count} invariant(s) have potential threats."
    )

    return InvariantReport(
        invariants=all_invariants,
        broken_invariant_count=broken_count,
        summary=summary,
    )


def _infer_balance_invariants(
    contract: ContractInfo,
    functions: list[FunctionInfo],
    source: str,
) -> list[Invariant]:
    """Infer balance-related invariants."""
    invariants: list[Invariant] = []

    # Check for balance mappings
    has_balance = any(v for v in contract.state_vars
                      if "balance" in v.lower() or "Balance" in v)
    has_total = _TOTAL_TRACKER.search(source)

    if has_balance and has_total:
        total_name = has_total.group("name") if has_total else "total"
        inv = Invariant(
            contract=contract.name,
            description=f"Sum of individual balances should equal {total_name}",
            kind="balance",
            confidence="high",
            source="inferred",
            evidence=f"Found balance mapping and {total_name} tracker",
            manual_checks=[
                f"Verify {total_name} is updated in every deposit/withdraw path",
                "Check for rounding errors in division operations",
                "Look for paths that update balances but not totals (or vice versa)",
            ],
        )
        # Find functions that update balances — they could break this
        for fn in functions:
            if fn.writes_state and ("balance" in fn.source.lower() or total_name in fn.source):
                inv.threatened_by.append(f"{contract.name}.{fn.name}")
        invariants.append(inv)

    # User cannot withdraw more than deposited
    if has_balance:
        withdraw_fns = [f for f in functions
                        if re.search(r'\b(withdraw|redeem|claim)\b', f.name, re.IGNORECASE)
                        and f.visibility in ("public", "external")]
        if withdraw_fns:
            inv = Invariant(
                contract=contract.name,
                description="Users cannot withdraw more than their balance",
                kind="balance",
                confidence="high",
                source="inferred",
                threatened_by=[f"{contract.name}.{f.name}" for f in withdraw_fns],
                evidence="Balance mapping + withdrawal functions found",
                manual_checks=[
                    "Verify balance check happens BEFORE transfer",
                    "Check for underflow in balance subtraction",
                    "Verify balance is decreased by exact withdrawal amount",
                    "Check if withdrawal can be called multiple times (reentrancy)",
                ],
            )
            invariants.append(inv)

    return invariants


def _infer_access_invariants(
    contract: ContractInfo,
    functions: list[FunctionInfo],
    flags: list[RiskFlag],
) -> list[Invariant]:
    """Infer access control invariants."""
    invariants: list[Invariant] = []

    # Find privileged functions
    admin_fns = [f for f in functions
                 if re.search(r'\b(onlyOwner|onlyAdmin|onlyRole|onlyGovernance)\b',
                              " ".join(f.modifiers) + " " + f.source)]

    if admin_fns:
        inv = Invariant(
            contract=contract.name,
            description="Only privileged roles can call admin functions",
            kind="access",
            confidence="high",
            source="inferred",
            evidence=f"Found {len(admin_fns)} admin-restricted function(s)",
            manual_checks=[
                "Verify ownership cannot be transferred to zero address",
                "Check if role can be escalated by non-admin",
                "Look for functions that bypass access control",
            ],
        )
        # Check if any unguarded functions write to the same state
        for fn in functions:
            if fn.visibility in ("public", "external") and fn.writes_state:
                has_guard = re.search(
                    r'\b(onlyOwner|onlyAdmin|onlyRole|onlyGovernance|requiresAuth)\b',
                    " ".join(fn.modifiers) + " " + fn.source
                )
                if not has_guard:
                    # Check if it writes to sensitive state vars
                    if re.search(r'\b(owner|admin|operator|paused|implementation)\b',
                                 fn.source, re.IGNORECASE):
                        inv.threatened_by.append(f"{contract.name}.{fn.name}")
        invariants.append(inv)

    # Pause invariant
    if any(v for v in contract.state_vars if "pause" in v.lower()):
        pause_fns = [f for f in functions if re.search(r'\bwhenNotPaused\b', f.source)]
        if pause_fns:
            inv = Invariant(
                contract=contract.name,
                description="Critical functions are disabled when contract is paused",
                kind="access",
                confidence="medium",
                source="inferred",
                evidence=f"{len(pause_fns)} function(s) use whenNotPaused",
                manual_checks=[
                    "Verify all fund-moving functions check pause state",
                    "Check that withdrawal is still possible when paused (emergency exit)",
                    "Verify pause can only be set by authorized roles",
                ],
            )
            # Fund-moving functions without pause check
            for fn in functions:
                if (fn.token_actions and fn.visibility in ("public", "external")
                        and not re.search(r'\bwhenNotPaused\b', fn.source)):
                    inv.threatened_by.append(f"{contract.name}.{fn.name}")
            invariants.append(inv)

    return invariants


def _infer_state_invariants(
    contract: ContractInfo,
    functions: list[FunctionInfo],
    source: str,
) -> list[Invariant]:
    """Infer state ordering and timing invariants."""
    invariants: list[Invariant] = []

    # Nonce should only increase
    if _NONCE_PATTERN.search(source):
        inv = Invariant(
            contract=contract.name,
            description="Nonce values should only increase and never repeat",
            kind="ordering",
            confidence="medium",
            source="inferred",
            evidence="Nonce state variable found",
            manual_checks=[
                "Verify nonce increments after each use",
                "Check that nonce is included in signature digest",
                "Look for nonce reuse via cross-chain replay",
            ],
        )
        for fn in functions:
            if _NONCE_PATTERN.search(fn.source) and fn.writes_state:
                inv.threatened_by.append(f"{contract.name}.{fn.name}")
        invariants.append(inv)

    # Deadline should be enforced
    if _DEADLINE_PATTERN.search(source):
        inv = Invariant(
            contract=contract.name,
            description="Time-locked operations should enforce their deadlines",
            kind="ordering",
            confidence="medium",
            source="inferred",
            evidence="Deadline/expiry variable found",
            manual_checks=[
                "Verify deadline is checked with block.timestamp",
                "Check for off-by-one in timestamp comparison (<= vs <)",
                "Verify deadline cannot be set to far future or zero",
            ],
        )
        for fn in functions:
            if (_DEADLINE_PATTERN.search(fn.source)
                    and not re.search(r'block\.timestamp', fn.source)):
                inv.threatened_by.append(f"{contract.name}.{fn.name}")
        invariants.append(inv)

    return invariants


def _infer_supply_invariants(
    contract: ContractInfo,
    functions: list[FunctionInfo],
    source: str,
) -> list[Invariant]:
    """Infer token supply invariants."""
    invariants: list[Invariant] = []

    if _SUPPLY_VAR.search(source):
        mint_fns = [f for f in functions
                    if re.search(r'\b_?mint\b', f.name, re.IGNORECASE)]
        burn_fns = [f for f in functions
                    if re.search(r'\b_?burn\b', f.name, re.IGNORECASE)]

        if mint_fns:
            inv = Invariant(
                contract=contract.name,
                description="totalSupply should equal sum of all mints minus burns",
                kind="supply",
                confidence="high",
                source="inferred",
                threatened_by=[f"{contract.name}.{f.name}" for f in mint_fns + burn_fns],
                evidence=f"Found totalSupply, {len(mint_fns)} mint fn(s), {len(burn_fns)} burn fn(s)",
                manual_checks=[
                    "Verify totalSupply is updated atomically with balance changes",
                    "Check for uncapped minting (infinite mint bug)",
                    "Verify burn cannot underflow totalSupply",
                ],
            )
            invariants.append(inv)

    # Share price should not decrease (for vault-like contracts)
    if _SHARE_PRICE.search(source):
        inv = Invariant(
            contract=contract.name,
            description="Share price / exchange rate should not decrease unexpectedly",
            kind="supply",
            confidence="medium",
            source="inferred",
            evidence="Share price or exchange rate calculation found",
            manual_checks=[
                "Verify donation attack is not possible (ERC4626 inflation attack)",
                "Check rounding direction favors the protocol",
                "Verify first depositor cannot manipulate share price",
                "Check if direct token transfer can inflate assets without minting shares",
            ],
        )
        for fn in functions:
            if fn.writes_state and fn.token_actions:
                inv.threatened_by.append(f"{contract.name}.{fn.name}")
        invariants.append(inv)

    return invariants


def _infer_init_invariants(
    contract: ContractInfo,
    functions: list[FunctionInfo],
    source: str,
) -> list[Invariant]:
    """Infer initialization invariants."""
    invariants: list[Invariant] = []

    init_fns = [f for f in functions
                if re.search(r'\b(initialize|reinitialize)\b', f.name, re.IGNORECASE)]

    if init_fns:
        inv = Invariant(
            contract=contract.name,
            description="Initialization functions can only be called once",
            kind="state",
            confidence="high",
            source="inferred",
            threatened_by=[f"{contract.name}.{f.name}" for f in init_fns],
            evidence=f"Found {len(init_fns)} initialization function(s)",
            manual_checks=[
                "Verify initializer modifier is present",
                "Check for reinitializer version gaps",
                "Verify no constructor in upgradeable proxy",
                "Check if uninitialized proxy can be taken over",
            ],
        )
        invariants.append(inv)

    return invariants
