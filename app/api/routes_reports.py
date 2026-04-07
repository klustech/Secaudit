"""Report export endpoints."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse, FileResponse

from app.services import storage, report_builder

router = APIRouter()


def _get_job(job_id: str):
    job = storage.load_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@router.get("/jobs/{job_id}/report.md")
async def get_markdown_report(job_id: str):
    """Return the markdown audit report."""
    job = _get_job(job_id)
    md = report_builder.build_markdown(job)
    return PlainTextResponse(content=md, media_type="text/markdown")


@router.get("/jobs/{job_id}/report.json")
async def get_json_report(job_id: str):
    """Return the full analysis as JSON."""
    job = _get_job(job_id)
    return job.model_dump()


@router.get("/jobs/{job_id}/report.csv")
async def get_csv_report(job_id: str):
    """Return risk flags as CSV."""
    job = _get_job(job_id)
    csv = report_builder.build_csv_findings(job)
    return PlainTextResponse(content=csv, media_type="text/csv")
