"""Regex-based Solidity parser for MVP.

Extracts contracts, functions, modifiers, events, errors, imports,
inheritance, and state variables using pattern matching. A full AST
parser (solidity-parser-antlr or tree-sitter) can replace this later.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.models.contract_info import ContractInfo
from app.models.function_info import FunctionInfo

# --- Regex patterns ---

_IMPORT_RE = re.compile(r'import\s+[^;]+;')
_CONTRACT_RE = re.compile(
    r'\b(contract|interface|library|abstract\s+contract)\s+'
    r'(?P<name>\w+)'
    r'(?:\s+is\s+(?P<bases>[^{]+))?'
    r'\s*\{',
    re.MULTILINE,
)
_FUNCTION_RE = re.compile(
    r'\bfunction\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)'
    r'(?P<rest>[^{;]*)[{;]',
    re.MULTILINE | re.DOTALL,
)
_MODIFIER_DEF_RE = re.compile(r'\bmodifier\s+(?P<name>\w+)\s*\(', re.MULTILINE)
_EVENT_RE = re.compile(r'\bevent\s+(?P<name>\w+)\s*\(', re.MULTILINE)
_ERROR_RE = re.compile(r'\berror\s+(?P<name>\w+)\s*\(', re.MULTILINE)
_STATE_VAR_RE = re.compile(
    r'^\s+(?:mapping|address|uint\d*|int\d*|bytes\d*|string|bool)\b[^;]+\b(?P<name>\w+)\s*[;=]',
    re.MULTILINE,
)
_VISIBILITY_RE = re.compile(r'\b(public|external|internal|private)\b')
_MUTABILITY_RE = re.compile(r'\b(view|pure|payable)\b')
_MODIFIER_USAGE_RE = re.compile(r'\b(only\w+|require\w*|nonReentrant|initializer|whenNotPaused)\b')

# Patterns that indicate state writes
_STATE_WRITE_INDICATORS = re.compile(
    r'(\w+\s*=\s*[^=]|\w+\s*\+=|\w+\s*-=|\w+\.push\(|delete\s+\w+)', re.MULTILINE
)

# External call patterns
_EXTERNAL_CALL_RE = re.compile(
    r'(\.\s*call\s*[({]|\.delegatecall\s*\(|\.staticcall\s*\(|'
    r'\.transfer\s*\(|\.send\s*\(|'
    r'\.safeTransfer\s*\(|\.safeTransferFrom\s*\(|'
    r'\.transferFrom\s*\(|\.approve\s*\()',
    re.MULTILINE,
)

# Token action patterns
_TOKEN_ACTION_RE = re.compile(
    r'\b(transfer|transferFrom|safeTransfer|safeTransferFrom|'
    r'approve|mint|burn|withdraw|claim|redeem|sweep|rescue)\s*\(',
    re.MULTILINE,
)


def parse_file(file_path: Path) -> tuple[list[ContractInfo], list[FunctionInfo]]:
    """Parse a single Solidity file and return contracts and functions."""
    source = file_path.read_text(errors="replace")
    rel_path = str(file_path)

    imports = [m.group(0).strip() for m in _IMPORT_RE.finditer(source)]

    contracts: list[ContractInfo] = []
    functions: list[FunctionInfo] = []

    for cm in _CONTRACT_RE.finditer(source):
        kind_raw = cm.group(1).strip()
        kind = kind_raw.split()[-1]  # "abstract contract" -> "contract"
        if "abstract" in kind_raw:
            kind = "abstract"
        name = cm.group("name")
        bases_raw = cm.group("bases") or ""
        bases = [b.strip().split("(")[0].strip() for b in bases_raw.split(",") if b.strip()]

        # Find the contract body (simple brace matching)
        start = cm.end() - 1
        body = _extract_braced_block(source, start)

        # Extract components from body
        modifiers_found = [m.group("name") for m in _MODIFIER_DEF_RE.finditer(body)]
        events_found = [m.group("name") for m in _EVENT_RE.finditer(body)]
        errors_found = [m.group("name") for m in _ERROR_RE.finditer(body)]
        state_vars = [m.group("name") for m in _STATE_VAR_RE.finditer(body)]

        func_names: list[str] = []
        for fm in _FUNCTION_RE.finditer(body):
            fn = _parse_function_match(fm, name, rel_path, body)
            functions.append(fn)
            func_names.append(fn.name)

        contracts.append(ContractInfo(
            name=name,
            file_path=rel_path,
            kind=kind,
            inherits=bases,
            imports=imports,
            functions=func_names,
            state_vars=state_vars,
            events=events_found,
            modifiers=modifiers_found,
            custom_errors=errors_found,
        ))

    return contracts, functions


def _parse_function_match(
    fm: re.Match, contract_name: str, file_path: str, body: str
) -> FunctionInfo:
    """Build a FunctionInfo from a function regex match."""
    name = fm.group("name")
    params = fm.group("params").strip()
    rest = fm.group("rest").strip()

    signature = f"{name}({params})"

    vis_m = _VISIBILITY_RE.search(rest)
    visibility = vis_m.group(1) if vis_m else "internal"

    mut_m = _MUTABILITY_RE.search(rest)
    mutability = mut_m.group(1) if mut_m else "nonpayable"

    modifiers = [m.group(1) for m in _MODIFIER_USAGE_RE.finditer(rest)]

    # Get function body for deeper analysis
    fn_start = fm.start()
    fn_body = ""
    brace_pos = body.find("{", fm.start())
    if brace_pos != -1:
        fn_body = _extract_braced_block(body, brace_pos)

    writes_state = bool(_STATE_WRITE_INDICATORS.search(fn_body)) if fn_body else False
    external_calls = list({m.group(0).strip() for m in _EXTERNAL_CALL_RE.finditer(fn_body)})
    token_actions = list({m.group(1) for m in _TOKEN_ACTION_RE.finditer(fn_body)})

    return FunctionInfo(
        contract=contract_name,
        file_path=file_path,
        name=name,
        signature=signature,
        visibility=visibility,
        mutability=mutability,
        modifiers=modifiers,
        writes_state=writes_state,
        external_calls=external_calls,
        token_actions=token_actions,
        source=fn_body[:2000],  # cap stored source
    )


def _extract_braced_block(source: str, start: int) -> str:
    """Extract text from an opening brace to its matching close brace."""
    if start >= len(source) or source[start] != "{":
        return ""
    depth = 0
    i = start
    while i < len(source):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
        i += 1
    return source[start:]  # unmatched, return rest


def parse_all(sol_files: list[Path]) -> tuple[list[ContractInfo], list[FunctionInfo]]:
    """Parse all Solidity files and return aggregated results."""
    all_contracts: list[ContractInfo] = []
    all_functions: list[FunctionInfo] = []
    for f in sol_files:
        try:
            contracts, functions = parse_file(f)
            all_contracts.extend(contracts)
            all_functions.extend(functions)
        except Exception:
            # Skip files that fail to parse
            continue
    return all_contracts, all_functions
