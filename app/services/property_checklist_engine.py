"""Property checklist engine — infers review properties that should hold.

Replaces invariant_engine.py with review-oriented output.
Never claims a property is violated — only that it should be verified.
"""

from __future__ import annotations

import re

from app.models.contract_info import ContractInfo
from app.models.function_info import FunctionInfo
from app.models.review_property import ReviewProperty, PropertyChecklistReport

# --- Patterns for property inference ---

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
_NONCE_PATTERN = re.compile(r'\bnonce\b', re.IGNORECASE)
_DEADLINE_PATTERN = re.compile(r'\b(deadline|expiry|validUntil)\b', re.IGNORECASE)
_INITIALIZED_PATTERN = re.compile(r'\b(initialized|_initialized)\b')
_ORACLE_PATTERN = re.compile(
    r'\b(latestRoundData|latestAnswer|getPrice|oracle|priceFeed)\b',
    re.IGNORECASE,
)
_SIG_PATTERN = re.compile(
    r'\b(ecrecover|ECDSA\.recover|isValidSignature|EIP712|permit)\b',
)
_FEE_PATTERN = re.compile(r'\b(fee|feeRate|feeBps|feePercent)\b', re.IGNORECASE)
_ADMIN_SETTER = re.compile(
    r'\b(setOwner|transferOwnership|setAdmin|setOperator|setFee|setConfig|'
    r'setParameter|updateConfig)\b',
    re.IGNORECASE,
)


class PropertyChecklistEngine:
    """Infer review properties and map them to relevant functions."""

    def infer_properties(
        self,
        contracts: list[ContractInfo],
        functions: list[FunctionInfo],
    ) -> PropertyChecklistReport:
        """Infer review properties from contract structure."""
        all_properties: list[ReviewProperty] = []

        for contract in contracts:
            if contract.kind in ("interface", "library"):
                continue

            contract_fns = [f for f in functions if f.contract == contract.name]
            contract_source = " ".join(f.source for f in contract_fns)

            all_properties.extend(
                self._infer_balance_properties(contract, contract_fns, contract_source)
            )
            all_properties.extend(
                self._infer_access_properties(contract, contract_fns)
            )
            all_properties.extend(
                self._infer_supply_properties(contract, contract_fns, contract_source)
            )
            all_properties.extend(
                self._infer_ordering_properties(contract, contract_fns, contract_source)
            )
            all_properties.extend(
                self._infer_init_properties(contract, contract_fns, contract_source)
            )
            all_properties.extend(
                self._infer_configuration_properties(contract, contract_fns, contract_source)
            )
            all_properties.extend(
                self._infer_oracle_properties(contract, contract_fns, contract_source)
            )
            all_properties.extend(
                self._infer_signature_properties(contract, contract_fns, contract_source)
            )

        summary = [
            f"Inferred {len(all_properties)} review property/properties across "
            f"{len(contracts)} contract(s).",
            "Each property should be verified against the listed related functions.",
        ]

        return PropertyChecklistReport(properties=all_properties, summary=summary)

    def map_related_functions(
        self,
        property_statement: str,
        functions: list[FunctionInfo],
    ) -> list[str]:
        """Map a property statement to related function names."""
        related: list[str] = []
        keywords = set(re.findall(r'\w+', property_statement.lower()))
        for fn in functions:
            fn_words = set(re.findall(r'\w+', (fn.name + " " + fn.source).lower()))
            if keywords & fn_words:
                related.append(f"{fn.contract}.{fn.name}")
        return related

    # -----------------------------------------------------------------
    # Property inference by kind
    # -----------------------------------------------------------------

    def _infer_balance_properties(
        self,
        contract: ContractInfo,
        functions: list[FunctionInfo],
        source: str,
    ) -> list[ReviewProperty]:
        properties: list[ReviewProperty] = []
        has_balance = any(v for v in contract.state_vars
                         if "balance" in v.lower() or "Balance" in v)
        has_total = _TOTAL_TRACKER.search(source)

        if has_balance and has_total:
            total_name = has_total.group("name") if has_total else "total"
            related = [
                f"{contract.name}.{fn.name}" for fn in functions
                if fn.writes_state and ("balance" in fn.source.lower() or total_name in fn.source)
            ]
            properties.append(ReviewProperty(
                kind="balance",
                statement=f"Sum of individual balances should equal {total_name}",
                rationale=f"Found balance mapping and {total_name} tracker — "
                          f"these should stay synchronized across all state-changing paths",
                related_functions=related,
                confidence="high",
                manual_checks=[
                    f"Verify {total_name} is updated in every deposit/withdraw path",
                    "Check for rounding errors in division operations",
                    "Look for paths that update balances but not totals (or vice versa)",
                ],
            ))

        if has_balance:
            withdraw_fns = [f for f in functions
                           if re.search(r'\b(withdraw|redeem|claim)\b', f.name, re.IGNORECASE)
                           and f.visibility in ("public", "external")]
            if withdraw_fns:
                properties.append(ReviewProperty(
                    kind="balance",
                    statement="User withdrawals should not exceed recorded entitlement",
                    rationale="Balance mapping + withdrawal functions found — "
                              "verify withdrawal is bounded by recorded balance",
                    related_functions=[f"{contract.name}.{f.name}" for f in withdraw_fns],
                    confidence="high",
                    manual_checks=[
                        "Verify balance check happens BEFORE transfer",
                        "Check for underflow in balance subtraction",
                        "Verify balance is decreased by exact withdrawal amount",
                        "Verify withdrawal cannot be repeated via reentrancy",
                    ],
                ))

        return properties

    def _infer_access_properties(
        self,
        contract: ContractInfo,
        functions: list[FunctionInfo],
    ) -> list[ReviewProperty]:
        properties: list[ReviewProperty] = []

        admin_fns = [f for f in functions
                     if re.search(r'\b(onlyOwner|onlyAdmin|onlyRole|onlyGovernance)\b',
                                  " ".join(f.modifiers) + " " + f.source)]

        if admin_fns:
            related = [f"{contract.name}.{f.name}" for f in admin_fns]
            # Find unguarded functions that write sensitive state
            for fn in functions:
                if fn.visibility in ("public", "external") and fn.writes_state:
                    has_guard = re.search(
                        r'\b(onlyOwner|onlyAdmin|onlyRole|onlyGovernance|requiresAuth)\b',
                        " ".join(fn.modifiers) + " " + fn.source
                    )
                    if not has_guard and re.search(
                        r'\b(owner|admin|operator|paused|implementation)\b',
                        fn.source, re.IGNORECASE
                    ):
                        related.append(f"{contract.name}.{fn.name}")

            properties.append(ReviewProperty(
                kind="access",
                statement="Only privileged roles should be able to call admin functions",
                rationale=f"Found {len(admin_fns)} admin-restricted function(s) — "
                          f"verify no unguarded path can modify privileged state",
                related_functions=list(dict.fromkeys(related)),
                confidence="high",
                manual_checks=[
                    "Verify ownership cannot be transferred to zero address",
                    "Check if role can be escalated by non-admin",
                    "Look for functions that bypass access control",
                ],
            ))

        if any(v for v in contract.state_vars if "pause" in v.lower()):
            pause_fns = [f for f in functions if re.search(r'\bwhenNotPaused\b', f.source)]
            if pause_fns:
                related = [f"{contract.name}.{f.name}" for f in pause_fns]
                for fn in functions:
                    if (fn.token_actions and fn.visibility in ("public", "external")
                            and not re.search(r'\bwhenNotPaused\b', fn.source)):
                        related.append(f"{contract.name}.{fn.name}")

                properties.append(ReviewProperty(
                    kind="access",
                    statement="Critical functions are disabled when contract is paused",
                    rationale=f"{len(pause_fns)} function(s) use whenNotPaused — "
                              f"verify all fund-moving functions check pause state",
                    related_functions=list(dict.fromkeys(related)),
                    confidence="medium",
                    manual_checks=[
                        "Verify all fund-moving functions check pause state",
                        "Check that withdrawal is still possible when paused (emergency exit)",
                        "Verify pause can only be set by authorized roles",
                    ],
                ))

        return properties

    def _infer_supply_properties(
        self,
        contract: ContractInfo,
        functions: list[FunctionInfo],
        source: str,
    ) -> list[ReviewProperty]:
        properties: list[ReviewProperty] = []

        if _SUPPLY_VAR.search(source):
            mint_fns = [f for f in functions if re.search(r'\b_?mint\b', f.name, re.IGNORECASE)]
            burn_fns = [f for f in functions if re.search(r'\b_?burn\b', f.name, re.IGNORECASE)]
            if mint_fns:
                properties.append(ReviewProperty(
                    kind="supply",
                    statement="totalSupply should equal sum of all mints minus burns",
                    rationale=f"Found totalSupply, {len(mint_fns)} mint fn(s), {len(burn_fns)} burn fn(s)",
                    related_functions=[f"{contract.name}.{f.name}" for f in mint_fns + burn_fns],
                    confidence="high",
                    manual_checks=[
                        "Verify totalSupply is updated atomically with balance changes",
                        "Check for uncapped minting",
                        "Verify burn cannot underflow totalSupply",
                    ],
                ))

        if _SHARE_PRICE.search(source):
            related = [
                f"{contract.name}.{fn.name}" for fn in functions
                if fn.writes_state and fn.token_actions
            ]
            properties.append(ReviewProperty(
                kind="supply",
                statement="Share price / exchange rate should not decrease unexpectedly",
                rationale="Share price or exchange rate calculation found",
                related_functions=related,
                confidence="medium",
                manual_checks=[
                    "Verify donation attack is not possible (ERC4626 inflation attack)",
                    "Check rounding direction favors the protocol",
                    "Verify first depositor cannot manipulate share price",
                    "Check if direct token transfer can inflate assets without minting shares",
                ],
            ))

        return properties

    def _infer_ordering_properties(
        self,
        contract: ContractInfo,
        functions: list[FunctionInfo],
        source: str,
    ) -> list[ReviewProperty]:
        properties: list[ReviewProperty] = []

        if _NONCE_PATTERN.search(source):
            related = [
                f"{contract.name}.{fn.name}" for fn in functions
                if _NONCE_PATTERN.search(fn.source) and fn.writes_state
            ]
            properties.append(ReviewProperty(
                kind="ordering",
                statement="Nonce values should only increase and never repeat",
                rationale="Nonce state variable found",
                related_functions=related,
                confidence="medium",
                manual_checks=[
                    "Verify nonce increments after each use",
                    "Check that nonce is included in signature digest",
                    "Look for nonce reuse via cross-chain replay",
                ],
            ))

        if _DEADLINE_PATTERN.search(source):
            related = [
                f"{contract.name}.{fn.name}" for fn in functions
                if _DEADLINE_PATTERN.search(fn.source)
                and not re.search(r'block\.timestamp', fn.source)
            ]
            properties.append(ReviewProperty(
                kind="ordering",
                statement="Time-locked operations should enforce their deadlines",
                rationale="Deadline/expiry variable found",
                related_functions=related,
                confidence="medium",
                manual_checks=[
                    "Verify deadline is checked with block.timestamp",
                    "Check for off-by-one in timestamp comparison (<= vs <)",
                    "Verify deadline cannot be set to far future or zero",
                ],
            ))

        return properties

    def _infer_init_properties(
        self,
        contract: ContractInfo,
        functions: list[FunctionInfo],
        source: str,
    ) -> list[ReviewProperty]:
        properties: list[ReviewProperty] = []

        init_fns = [f for f in functions
                    if re.search(r'\b(initialize|reinitialize)\b', f.name, re.IGNORECASE)]
        if init_fns:
            properties.append(ReviewProperty(
                kind="initialization",
                statement="Initialization logic should only succeed once",
                rationale=f"Found {len(init_fns)} initialization function(s)",
                related_functions=[f"{contract.name}.{f.name}" for f in init_fns],
                confidence="high",
                manual_checks=[
                    "Verify initializer modifier is present",
                    "Check for reinitializer version gaps",
                    "Verify no constructor in upgradeable proxy",
                    "Check if uninitialized proxy can be taken over",
                ],
            ))

        return properties

    def _infer_configuration_properties(
        self,
        contract: ContractInfo,
        functions: list[FunctionInfo],
        source: str,
    ) -> list[ReviewProperty]:
        properties: list[ReviewProperty] = []

        config_fns = [f for f in functions if _ADMIN_SETTER.search(f.name)]
        if config_fns:
            properties.append(ReviewProperty(
                kind="configuration",
                statement="Only privileged roles should be able to change fee parameters",
                rationale=f"Found {len(config_fns)} configuration/admin setter function(s)",
                related_functions=[f"{contract.name}.{f.name}" for f in config_fns],
                confidence="medium",
                manual_checks=[
                    "Verify each setter has appropriate access control",
                    "Check for reasonable bounds on configurable values",
                    "Verify configuration changes emit events for off-chain monitoring",
                ],
            ))

        return properties

    def _infer_oracle_properties(
        self,
        contract: ContractInfo,
        functions: list[FunctionInfo],
        source: str,
    ) -> list[ReviewProperty]:
        properties: list[ReviewProperty] = []

        if _ORACLE_PATTERN.search(source):
            related = [
                f"{contract.name}.{fn.name}" for fn in functions
                if _ORACLE_PATTERN.search(fn.source)
            ]
            properties.append(ReviewProperty(
                kind="oracle",
                statement="Oracle-derived values should be validated for freshness and non-zero responses",
                rationale="Oracle read pattern found in contract",
                related_functions=related,
                confidence="medium",
                manual_checks=[
                    "Check for staleness validation (updatedAt + heartbeat)",
                    "Verify zero/negative price is rejected",
                    "Consider manipulation resistance (TWAP, multiple sources)",
                ],
            ))

        return properties

    def _infer_signature_properties(
        self,
        contract: ContractInfo,
        functions: list[FunctionInfo],
        source: str,
    ) -> list[ReviewProperty]:
        properties: list[ReviewProperty] = []

        if _SIG_PATTERN.search(source):
            related = [
                f"{contract.name}.{fn.name}" for fn in functions
                if _SIG_PATTERN.search(fn.source)
            ]
            properties.append(ReviewProperty(
                kind="signature",
                statement="Signature-based authorization should bind nonce, chain, and deadline if intended",
                rationale="Signature verification pattern found in contract",
                related_functions=related,
                confidence="medium",
                manual_checks=[
                    "Verify nonce prevents signature replay",
                    "Check domain separator includes chain ID and contract address",
                    "Verify deadline/expiry is enforced",
                    "Confirm ecrecover result is checked for address(0)",
                ],
            ))

        return properties


# --- Convenience function for pipeline compatibility ---

def infer_review_properties(
    contracts: list[ContractInfo],
    functions: list[FunctionInfo],
) -> PropertyChecklistReport:
    """Top-level entry point matching the old infer_invariants signature."""
    engine = PropertyChecklistEngine()
    return engine.infer_properties(contracts, functions)
