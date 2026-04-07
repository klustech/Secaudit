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
