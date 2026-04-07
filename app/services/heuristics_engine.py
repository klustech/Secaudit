"""Rule-based risk heuristics for Solidity contracts and functions."""

from __future__ import annotations

import re
from app.models.function_info import FunctionInfo
from app.models.contract_info import ContractInfo
from app.models.risk_flag import RiskFlag


# --- Access control heuristics ---

_ACCESS_MODIFIERS = re.compile(
    r'\b(onlyOwner|onlyAdmin|onlyRole|onlyOperator|onlyGuardian|'
    r'onlyGovernance|onlyMinter|onlyPauser|requiresAuth|auth)\b',
    re.IGNORECASE,
)

_ADMIN_SETTERS = re.compile(
    r'\b(setOwner|transferOwnership|setAdmin|setOperator|setGuardian|'
    r'addSigner|removeSigner|addModule|removeModule|grantRole|revokeRole)\b',
    re.IGNORECASE,
)

_PAUSE_PATTERNS = re.compile(r'\b(pause|unpause|setPaused|togglePause)\b', re.IGNORECASE)
_UPGRADE_PATTERNS = re.compile(r'\b(upgradeTo|upgradeToAndCall|setImplementation|_authorizeUpgrade)\b', re.IGNORECASE)

# --- Funds flow ---

_FUND_MOVEMENT = re.compile(
    r'\b(transfer|transferFrom|safeTransfer|safeTransferFrom|'
    r'approve|call\{value|withdraw|claim|redeem|sweep|rescue|mint|burn)\b',
)

# --- External call ---

_EXTERNAL_CALLS = re.compile(
    r'(\.\s*call\s*[({]|\.delegatecall\s*\(|\.staticcall\s*\()',
)

_ARBITRARY_TARGET = re.compile(
    r'\b(target|to|recipient|dest)\s*\.\s*call\b',
)

# --- Timelock ---

_TIMELOCK_PATTERNS = re.compile(
    r'\b(queue|execute|cancel|delay|timelock|cooldown|eta|nonce)\b',
    re.IGNORECASE,
)

_TIMESTAMP_CMP = re.compile(r'block\.timestamp\s*[<>=]')

# --- Initialization ---

_INIT_PATTERNS = re.compile(
    r'\b(initialize|reinitialize|initializer|initialized)\b',
    re.IGNORECASE,
)

# --- Oracle ---

_ORACLE_PATTERNS = re.compile(
    r'\b(latestRoundData|latestAnswer|getPrice|oracle|priceFeed|chainlink)\b',
    re.IGNORECASE,
)

# --- Signature ---

_SIG_PATTERNS = re.compile(
    r'\b(ecrecover|ECDSA\.recover|isValidSignature|EIP712|signTypedData|permit)\b',
)


def analyze_function(fn: FunctionInfo) -> list[RiskFlag]:
    """Run all heuristic rules against a single function."""
    flags: list[RiskFlag] = []
    source = fn.source

    # Access control: public/external + writes state + no access modifier
    if fn.visibility in ("public", "external") and fn.writes_state:
        if not _ACCESS_MODIFIERS.search(" ".join(fn.modifiers)) and not _ACCESS_MODIFIERS.search(source):
            flags.append(RiskFlag(
                severity="high",
                category="access-control",
                file_path=fn.file_path,
                contract=fn.contract,
                function=fn.name,
                evidence=f"Public/external function '{fn.signature}' writes state with no obvious access control",
                explanation="Function is externally callable and modifies state without a visible modifier restricting access.",
                source="heuristic",
                manual_validation=[
                    f"Verify whether {fn.name} should be access-restricted",
                    "Check if access control is enforced via internal require/if checks",
                ],
            ))

    # Admin setter detection
    if _ADMIN_SETTERS.search(fn.name):
        flags.append(RiskFlag(
            severity="medium",
            category="access-control",
            file_path=fn.file_path,
            contract=fn.contract,
            function=fn.name,
            evidence=f"Function '{fn.name}' appears to set privileged roles or signers",
            explanation="Role/signer management functions are sensitive — verify proper access control.",
            source="heuristic",
            manual_validation=[
                f"Confirm only authorized callers can invoke {fn.name}",
                "Check for two-step ownership transfer patterns",
            ],
        ))

    # Pause/unpause
    if _PAUSE_PATTERNS.search(fn.name):
        flags.append(RiskFlag(
            severity="medium",
            category="access-control",
            file_path=fn.file_path,
            contract=fn.contract,
            function=fn.name,
            evidence=f"Pause-related function '{fn.name}' detected",
            explanation="Pause functionality can halt protocol operations — verify authorization.",
            source="heuristic",
            manual_validation=[
                f"Verify who can call {fn.name}",
                "Check if pause can be used to grief users",
            ],
        ))

    # Upgrade
    if _UPGRADE_PATTERNS.search(fn.name) or _UPGRADE_PATTERNS.search(source):
        flags.append(RiskFlag(
            severity="high",
            category="upgradeability",
            file_path=fn.file_path,
            contract=fn.contract,
            function=fn.name,
            evidence=f"Upgrade-related logic in '{fn.name}'",
            explanation="Upgrade functions can replace contract logic entirely — high trust boundary.",
            source="heuristic",
            manual_validation=[
                "Verify upgrade authorization is properly restricted",
                "Check for storage layout compatibility requirements",
                "Look for timelock on upgrades",
            ],
        ))

    # Fund movement
    if fn.token_actions or _FUND_MOVEMENT.search(source):
        sev = "high" if fn.visibility in ("public", "external") else "medium"
        flags.append(RiskFlag(
            severity=sev,
            category="funds-flow",
            file_path=fn.file_path,
            contract=fn.contract,
            function=fn.name,
            evidence=f"Token/value movement detected in '{fn.name}': {fn.token_actions or ['low-level call']}",
            explanation="Function moves tokens or native value — verify amounts, recipients, and reentrancy safety.",
            source="heuristic",
            manual_validation=[
                "Verify transfer amounts and recipients are correct",
                "Check for reentrancy guards if external calls precede state updates",
                "Confirm withdrawal/claim cannot be replayed",
            ],
        ))

    # External calls
    if fn.external_calls or _EXTERNAL_CALLS.search(source):
        sev = "high" if _ARBITRARY_TARGET.search(source) else "medium"
        flags.append(RiskFlag(
            severity=sev,
            category="external-call",
            file_path=fn.file_path,
            contract=fn.contract,
            function=fn.name,
            evidence=f"External call(s) in '{fn.name}': {fn.external_calls}",
            explanation="External calls can introduce reentrancy or unexpected behavior.",
            source="heuristic",
            manual_validation=[
                "Verify call targets are trusted or validated",
                "Check for checks-effects-interactions pattern",
                "Look for return value validation",
            ],
        ))

    # Timelock patterns
    if _TIMELOCK_PATTERNS.search(source) or _TIMESTAMP_CMP.search(source):
        flags.append(RiskFlag(
            severity="medium",
            category="timelock-queue",
            file_path=fn.file_path,
            contract=fn.contract,
            function=fn.name,
            evidence=f"Timelock/queue pattern in '{fn.name}'",
            explanation="Timelock logic — verify delays cannot be bypassed and IDs cannot be replayed.",
            source="heuristic",
            manual_validation=[
                "Check minimum delay enforcement",
                "Verify queue IDs are unique and non-replayable",
                "Confirm cancel logic is properly authorized",
            ],
        ))

    # Initialization
    if _INIT_PATTERNS.search(fn.name) or _INIT_PATTERNS.search(source):
        flags.append(RiskFlag(
            severity="high",
            category="initialization",
            file_path=fn.file_path,
            contract=fn.contract,
            function=fn.name,
            evidence=f"Initialization logic in '{fn.name}'",
            explanation="Initialize functions in upgradeable contracts must only run once.",
            source="heuristic",
            manual_validation=[
                "Verify initializer modifier or single-use guard is present",
                "Check that all critical state is set during initialization",
                "Confirm reinitialize cannot be called maliciously",
            ],
        ))

    # Oracle reads
    if _ORACLE_PATTERNS.search(source):
        flags.append(RiskFlag(
            severity="medium",
            category="oracle-dependency",
            file_path=fn.file_path,
            contract=fn.contract,
            function=fn.name,
            evidence=f"Oracle read in '{fn.name}'",
            explanation="Oracle-dependent logic — verify staleness checks and fallback behavior.",
            source="heuristic",
            manual_validation=[
                "Check for stale price data handling",
                "Verify oracle cannot return zero or negative values unchecked",
                "Look for manipulation resistance (TWAP, multiple sources)",
            ],
        ))

    # Signature verification
    if _SIG_PATTERNS.search(source):
        flags.append(RiskFlag(
            severity="medium",
            category="signature-auth",
            file_path=fn.file_path,
            contract=fn.contract,
            function=fn.name,
            evidence=f"Signature verification in '{fn.name}'",
            explanation="Signature-based auth — verify replay protection and signer validation.",
            source="heuristic",
            manual_validation=[
                "Verify nonce or deadline prevents signature replay",
                "Check domain separator includes chain ID",
                "Confirm ecrecover result is checked for address(0)",
            ],
        ))

    return flags


def analyze_all(functions: list[FunctionInfo]) -> list[RiskFlag]:
    """Run heuristics on all functions and return all flags."""
    all_flags: list[RiskFlag] = []
    for fn in functions:
        all_flags.extend(analyze_function(fn))

    # Add risk tags back to functions
    for fn in functions:
        fn_flags = [f for f in all_flags if f.function == fn.name and f.contract == fn.contract]
        fn.risk_tags = list({f.category for f in fn_flags})

    return all_flags
