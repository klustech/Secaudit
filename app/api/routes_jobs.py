"""Job status and data retrieval endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.services import storage

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
    return {"flags": [f.model_dump() for f in flags]}


# --- New review-oriented endpoints ---


@router.get("/jobs/{job_id}/value-movements")
async def get_value_movements(job_id: str):
    """Get value movement analysis."""
    job = _get_job(job_id)
    return job.value_movements.model_dump()


@router.get("/jobs/{job_id}/review-properties")
async def get_review_properties(job_id: str):
    """Get inferred review properties."""
    job = _get_job(job_id)
    return job.review_properties.model_dump()


@router.get("/jobs/{job_id}/risk-scenarios")
async def get_risk_scenarios(job_id: str, severity: str | None = None):
    """Get risk scenarios for manual review."""
    job = _get_job(job_id)
    data = job.risk_scenarios.model_dump()
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

    return {
        "high_priority_checks": list(dict.fromkeys(high_checks)),
        "medium_priority_checks": list(dict.fromkeys(medium_checks)),
    }


# --- Deprecated adapter endpoints (backward compatibility) ---


@router.get("/jobs/{job_id}/fund-flows")
async def get_fund_flows(job_id: str):
    """[Deprecated] Get fund flow analysis — use /value-movements instead."""
    job = _get_job(job_id)
    return job.fund_flows.model_dump()


@router.get("/jobs/{job_id}/invariants")
async def get_invariants(job_id: str):
    """[Deprecated] Get inferred invariants — use /review-properties instead."""
    job = _get_job(job_id)
    return job.invariants.model_dump()


@router.get("/jobs/{job_id}/attack-surface")
async def get_attack_surface(job_id: str, severity: str | None = None):
    """[Deprecated] Get attack surface analysis — use /risk-scenarios instead."""
    job = _get_job(job_id)
    data = job.attack_surface.model_dump()
    if severity:
        data["paths"] = [p for p in data["paths"] if p["severity"] == severity]
    return data
