"""Job status and data retrieval endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.services import storage
from app.services.safety_filter import sanitize_dict, sanitize_text
from app.models.fund_flow import FundFlowEdge, FundFlowGraph
from app.models.attack_surface import Invariant, InvariantReport
from app.models.attack_path import AttackPath, AttackSurfaceReport

router = APIRouter()


def _get_job(job_id: str):
    job = storage.load_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@router.get("/jobs/{job_id}")
async def get_job_status(job_id: str):
    """Get job status and progress."""
    job = _get_job(job_id)
    return {
        "job_id": job.job_id,
        "status": job.status,
        "progress": job.progress,
        "error": job.error,
    }


@router.get("/jobs/{job_id}/summary")
async def get_job_summary(job_id: str):
    """Get the top-level analysis summary."""
    job = _get_job(job_id)
    return {
        "job_id": job.job_id,
        "repo_url": job.repo_url,
        "ref": job.ref,
        "commit": job.commit,
        "status": job.status,
        "files_scanned": job.files_scanned,
        "solidity_files": job.solidity_files,
        "language_mix": job.language_mix,
        "contracts_count": len(job.contracts),
        "functions_count": len(job.functions),
        "risk_flags_count": len(job.risk_flags),
        "notes": job.notes,
    }


@router.get("/jobs/{job_id}/contracts")
async def get_contracts(job_id: str):
    """Get the list of parsed contracts."""
    job = _get_job(job_id)
    return {"contracts": [c.model_dump() for c in job.contracts]}


@router.get("/jobs/{job_id}/functions")
async def get_functions(job_id: str, contract: str | None = None, risk_only: bool = False):
    """Get function list, with optional filters."""
    job = _get_job(job_id)
    fns = job.functions
    if contract:
        fns = [f for f in fns if f.contract == contract]
    if risk_only:
        fns = [f for f in fns if f.risk_tags]
    return {"functions": [f.model_dump() for f in fns]}


@router.get("/jobs/{job_id}/flags")
async def get_flags(job_id: str, severity: str | None = None, category: str | None = None):
    """Get risk flags with optional filters."""
    job = _get_job(job_id)
    flags = job.risk_flags
    if severity:
        flags = [f for f in flags if f.severity == severity]
    if category:
        flags = [f for f in flags if f.category == category]
    return {"flags": [sanitize_dict(f.model_dump()) for f in flags]}


# --- New review-oriented endpoints ---


@router.get("/jobs/{job_id}/value-movements")
async def get_value_movements(job_id: str):
    """Get value movement analysis."""
    job = _get_job(job_id)
    return sanitize_dict(job.value_movements.model_dump())


@router.get("/jobs/{job_id}/review-properties")
async def get_review_properties(job_id: str):
    """Get inferred review properties."""
    job = _get_job(job_id)
    return sanitize_dict(job.review_properties.model_dump())


@router.get("/jobs/{job_id}/risk-scenarios")
async def get_risk_scenarios(job_id: str, severity: str | None = None):
    """Get risk scenarios for manual review."""
    job = _get_job(job_id)
    data = sanitize_dict(job.risk_scenarios.model_dump())
    if severity:
        data["scenarios"] = [s for s in data["scenarios"] if s["severity_hint"] == severity]
    return data


@router.get("/jobs/{job_id}/review-worklist")
async def get_review_worklist(job_id: str):
    """Get a prioritized review worklist merging all three analyses."""
    job = _get_job(job_id)

    high_checks: list[str] = []
    medium_checks: list[str] = []

    # From risk scenarios
    for scenario in job.risk_scenarios.scenarios:
        for step in scenario.manual_validation_steps:
            if scenario.severity_hint == "high":
                high_checks.append(step)
            else:
                medium_checks.append(step)

    # From value movements — unguarded caller-directed outflows
    for edge in job.value_movements.edges:
        if edge.direction == "outflow" and edge.caller_influenced and not edge.access_controlled:
            for check in edge.manual_checks:
                if check not in high_checks:
                    high_checks.append(check)

    # From review properties
    for prop in job.review_properties.properties:
        if prop.confidence == "high":
            for check in prop.manual_checks:
                if check not in high_checks:
                    high_checks.append(check)
        else:
            for check in prop.manual_checks:
                if check not in medium_checks:
                    medium_checks.append(check)

    return sanitize_dict({
        "high_priority_checks": list(dict.fromkeys(high_checks)),
        "medium_priority_checks": list(dict.fromkeys(medium_checks)),
    })


# --- Consolidated review dashboard ---


@router.get("/jobs/{job_id}/review-dashboard")
async def get_review_dashboard(job_id: str):
    """One-page reviewer-focused payload with the top items from every analysis.

    Designed so an iPad user can open one page and immediately know what to
    inspect next without jumping across tabs.
    """
    job = _get_job(job_id)

    # Top 10 high-priority checks (from review-worklist logic)
    high_checks: list[str] = []
    for scenario in job.risk_scenarios.scenarios:
        if scenario.severity_hint == "high":
            for step in scenario.manual_validation_steps:
                if step not in high_checks:
                    high_checks.append(step)
    for edge in job.value_movements.edges:
        if edge.direction == "outflow" and edge.caller_influenced and not edge.access_controlled:
            for check in edge.manual_checks:
                if check not in high_checks:
                    high_checks.append(check)
    for prop in job.review_properties.properties:
        if prop.confidence == "high":
            for check in prop.manual_checks:
                if check not in high_checks:
                    high_checks.append(check)

    # Top flagged contracts (by flag count, descending)
    contract_flag_counts: dict[str, int] = {}
    for flag in job.risk_flags:
        if flag.severity in ("critical", "high"):
            contract_flag_counts[flag.contract] = contract_flag_counts.get(flag.contract, 0) + 1
    top_flagged_contracts = sorted(
        contract_flag_counts.items(), key=lambda x: x[1], reverse=True
    )[:10]

    # Top value-moving functions (unguarded, caller-influenced outflows first)
    risky_edges = [
        e for e in job.value_movements.edges
        if e.direction == "outflow"
    ]
    risky_edges.sort(key=lambda e: (
        not (e.caller_influenced and not e.access_controlled),
        e.confidence != "high",
    ))
    top_value_functions = [
        {
            "contract": e.contract,
            "function": e.function,
            "direction": e.direction,
            "asset_type": e.asset_type,
            "caller_influenced": e.caller_influenced,
            "access_controlled": e.access_controlled,
            "confidence": e.confidence,
            "top_check": e.manual_checks[0] if e.manual_checks else "",
        }
        for e in risky_edges[:10]
    ]

    # Top review properties
    sorted_props = sorted(
        job.review_properties.properties,
        key=lambda p: {"high": 0, "medium": 1, "low": 2}.get(p.confidence, 3),
    )
    top_properties = [
        {
            "kind": p.kind,
            "statement": p.statement,
            "confidence": p.confidence,
            "source_type": p.source_type,
            "related_functions_count": len(p.related_functions),
            "top_check": p.manual_checks[0] if p.manual_checks else "",
        }
        for p in sorted_props[:10]
    ]

    # Top risk scenarios
    sorted_scenarios = sorted(
        job.risk_scenarios.scenarios,
        key=lambda s: {"high": 0, "medium": 1, "low": 2}.get(s.severity_hint, 3),
    )
    top_scenarios = [
        {
            "title": s.title,
            "category": s.category,
            "severity_hint": s.severity_hint,
            "source_type": s.source_type,
            "affected_functions_count": len(s.affected_functions),
            "top_step": s.manual_validation_steps[0] if s.manual_validation_steps else "",
        }
        for s in sorted_scenarios[:10]
    ]

    dashboard = {
        "job_id": job.job_id,
        "repo_url": job.repo_url,
        "status": job.status,
        "overview": {
            "contracts_count": len(job.contracts),
            "functions_count": len(job.functions),
            "risk_flags_count": len(job.risk_flags),
            "value_movement_edges": len(job.value_movements.edges),
            "review_properties_count": len(job.review_properties.properties),
            "risk_scenarios_count": len(job.risk_scenarios.scenarios),
        },
        "top_priority_checks": high_checks[:10],
        "top_flagged_contracts": [
            {"contract": name, "high_critical_flags": count}
            for name, count in top_flagged_contracts
        ],
        "top_value_moving_functions": top_value_functions,
        "top_review_properties": top_properties,
        "top_risk_scenarios": top_scenarios,
        "export_links": {
            "markdown_report": f"/jobs/{job_id}/report.md",
            "json_report": f"/jobs/{job_id}/report.json",
            "csv_findings": f"/jobs/{job_id}/report.csv",
        },
    }

    return sanitize_dict(dashboard)


# --- Deprecated adapter endpoints (backward compatibility) ---
# These transform the new analysis structures into the old response shapes.


def _adapt_fund_flows(job) -> dict:
    """Transform value_movements into the legacy fund_flows shape."""
    vm = job.value_movements
    edges = []
    entry_points = []
    exit_points = []
    internal_moves = []
    unguarded_exits = []

    for edge in vm.edges:
        fn_label = f"{edge.contract}.{edge.function}"
        ff_edge = FundFlowEdge(
            source_contract=edge.contract,
            source_function=edge.function,
            sink_contract=edge.contract,
            sink_function=edge.function,
            mechanism=edge.mechanism,
            token="ETH" if edge.asset_type == "eth" else edge.asset_type.upper(),
            sender=edge.source_hint or "unknown",
            recipient=edge.destination_hint or "unknown",
            guarded=edge.access_controlled,
            guard_details="access-controlled" if edge.access_controlled else "",
            reentrancy_safe=not edge.external_interaction or edge.access_controlled,
            evidence="; ".join(edge.notes),
        )
        edges.append(ff_edge)

        if edge.direction == "inflow":
            entry_points.append(fn_label)
        elif edge.direction == "outflow":
            exit_points.append(fn_label)
            if not edge.access_controlled:
                unguarded_exits.append(fn_label)
        elif edge.direction == "internal":
            internal_moves.append(fn_label)

    summary = "; ".join(vm.summary) if vm.summary else "Adapted from value movement analysis."
    graph = FundFlowGraph(
        edges=edges,
        entry_points=list(dict.fromkeys(entry_points)),
        exit_points=list(dict.fromkeys(exit_points)),
        internal_moves=list(dict.fromkeys(internal_moves)),
        unguarded_exits=list(dict.fromkeys(unguarded_exits)),
        summary=summary,
    )
    return sanitize_dict(graph.model_dump())


def _adapt_invariants(job) -> dict:
    """Transform review_properties into the legacy invariants shape."""
    rp = job.review_properties
    invariants = []
    for prop in rp.properties:
        inv = Invariant(
            contract=prop.related_functions[0].split(".")[0] if prop.related_functions else "",
            description=prop.statement,
            kind=prop.kind,
            confidence=prop.confidence,
            source="inferred",
            threatened_by=prop.related_functions,
            evidence=prop.rationale,
            manual_checks=prop.manual_checks,
        )
        invariants.append(inv)

    summary = "; ".join(rp.summary) if rp.summary else "Adapted from review properties."
    report = InvariantReport(
        invariants=invariants,
        broken_invariant_count=0,
        summary=summary,
    )
    return sanitize_dict(report.model_dump())


_SCENARIO_SEVERITY_MAP = {"high": "high", "medium": "medium", "low": "low"}


def _adapt_attack_surface(job) -> dict:
    """Transform risk_scenarios into the legacy attack_surface shape."""
    rs = job.risk_scenarios
    paths = []
    critical_count = 0
    high_count = 0

    for i, scenario in enumerate(rs.scenarios):
        severity = _SCENARIO_SEVERITY_MAP.get(scenario.severity_hint, "medium")
        path = AttackPath(
            id=f"RS-{i + 1:03d}",
            title=scenario.title,
            severity=severity,
            preconditions=[scenario.risky_assumption],
            affected_functions=scenario.affected_functions,
            affected_contracts=list({
                fn.split(".")[0] for fn in scenario.affected_functions if "." in fn
            }),
            risk_category=scenario.category,
            consequence=scenario.why_it_matters,
            likelihood="requires-validation",
            evidence=[scenario.risky_assumption],
            why_concerning=scenario.why_it_matters,
            what_prevents_it="",
            validation_steps=scenario.manual_validation_steps,
        )
        paths.append(path)
        if severity == "critical":
            critical_count += 1
        elif severity == "high":
            high_count += 1

    summary = "; ".join(rs.summary) if rs.summary else "Adapted from risk scenarios."
    report = AttackSurfaceReport(
        paths=paths,
        critical_paths=critical_count,
        high_paths=high_count,
        summary=summary,
    )
    return sanitize_dict(report.model_dump())


@router.get("/jobs/{job_id}/fund-flows")
async def get_fund_flows(job_id: str):
    """[Deprecated] Get fund flow analysis — use /value-movements instead."""
    job = _get_job(job_id)
    return _adapt_fund_flows(job)


@router.get("/jobs/{job_id}/invariants")
async def get_invariants(job_id: str):
    """[Deprecated] Get inferred invariants — use /review-properties instead."""
    job = _get_job(job_id)
    return _adapt_invariants(job)


@router.get("/jobs/{job_id}/attack-surface")
async def get_attack_surface(job_id: str, severity: str | None = None):
    """[Deprecated] Get attack surface analysis — use /risk-scenarios instead."""
    job = _get_job(job_id)
    data = _adapt_attack_surface(job)
    if severity:
        data["paths"] = [p for p in data["paths"] if p["severity"] == severity]
    return data
