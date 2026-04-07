"""POST /analyze — start a new repo analysis job."""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, HTTPException

from app.models import AnalyzeRequest, RepoAnalysis
from app.services import repo_fetcher, file_scanner, solidity_parser, heuristics_engine
from app.services import fund_flow_analyzer, invariant_engine, attack_path_engine
from app.services import report_builder, storage
from app.utils.hashing import generate_job_id
from app.utils.github import is_valid_github_url

router = APIRouter()


async def _run_analysis(job_id: str, req: AnalyzeRequest) -> None:
    """Background task that performs the full analysis pipeline."""
    analysis = storage.load_job(job_id)
    if not analysis:
        return

    repo_root: Path | None = None
    try:
        # Step 1: Fetch repo
        analysis.status = "fetching"
        analysis.progress = "Downloading repository..."
        storage.save_job(analysis)

        repo_root = await repo_fetcher.fetch_repo(req.repo_url, req.ref)

        # Step 2: Scan files
        analysis.status = "scanning"
        analysis.progress = "Scanning files..."
        storage.save_job(analysis)

        file_map = file_scanner.scan_files(repo_root)
        analysis.language_mix = file_scanner.detect_language_mix(repo_root)
        analysis.files_scanned = sum(len(v) for v in file_map.values())
        analysis.solidity_files = len(file_map["solidity"])

        if not file_map["solidity"]:
            analysis.status = "completed"
            analysis.progress = "No Solidity files found."
            analysis.notes.append("No .sol files detected in repository.")
            storage.save_job(analysis)
            return

        # Step 3: Parse Solidity
        analysis.status = "parsing"
        analysis.progress = "Parsing Solidity files..."
        storage.save_job(analysis)

        contracts, functions = solidity_parser.parse_all(file_map["solidity"])
        analysis.contracts = contracts
        analysis.functions = functions

        # Step 4: Run heuristics
        analysis.status = "analyzing"
        analysis.progress = "Running heuristics..."
        storage.save_job(analysis)

        risk_flags = heuristics_engine.analyze_all(functions)
        analysis.risk_flags = risk_flags

        # Step 5: Trace fund flows
        analysis.status = "analyzing"
        analysis.progress = "Tracing fund flows..."
        storage.save_job(analysis)

        fund_flows = fund_flow_analyzer.analyze_fund_flows(contracts, functions)
        analysis.fund_flows = fund_flows

        # Step 6: Infer invariants
        analysis.progress = "Inferring invariants..."
        storage.save_job(analysis)

        invariants = invariant_engine.infer_invariants(contracts, functions, risk_flags)
        analysis.invariants = invariants

        # Step 7: Analyze attack surface
        analysis.progress = "Analyzing attack surface..."
        storage.save_job(analysis)

        attack_surface = attack_path_engine.analyze_attack_surface(
            contracts, functions, risk_flags, fund_flows, invariants
        )
        analysis.attack_surface = attack_surface

        # Step 8: Set review priorities based on flag counts
        for contract in analysis.contracts:
            fn_flags = [f for f in risk_flags
                        if f.contract == contract.name
                        and f.severity in ("critical", "high")]
            if len(fn_flags) >= 3:
                contract.review_priority = "high"
            elif fn_flags:
                contract.review_priority = "medium"
            else:
                contract.review_priority = "low"

        # Step 9: Add scope notes
        if req.scope_notes:
            analysis.notes.append(f"Scope notes: {req.scope_notes}")
        if req.docs_url:
            analysis.notes.append(f"Docs URL provided: {req.docs_url}")

        analysis.status = "completed"
        analysis.progress = "Analysis complete."
        storage.save_job(analysis)

        # Step 10: Save exports
        export_dir = Path("./data/exports") / job_id
        export_dir.mkdir(parents=True, exist_ok=True)
        (export_dir / "report.md").write_text(report_builder.build_markdown(analysis))
        (export_dir / "analysis.json").write_text(report_builder.build_json(analysis))
        (export_dir / "findings.csv").write_text(report_builder.build_csv_findings(analysis))

    except Exception as e:
        analysis.status = "error"
        analysis.error = str(e)
        analysis.progress = f"Error: {e}"
        storage.save_job(analysis)
    finally:
        # Clean up extracted repo
        if repo_root and repo_root.exists():
            shutil.rmtree(repo_root, ignore_errors=True)


@router.post("/analyze")
async def analyze(req: AnalyzeRequest, background_tasks: BackgroundTasks):
    """Start a new analysis job."""
    if not is_valid_github_url(req.repo_url):
        raise HTTPException(status_code=400, detail="Invalid GitHub repo URL")

    job_id = generate_job_id()

    analysis = RepoAnalysis(
        job_id=job_id,
        repo_url=req.repo_url,
        ref=req.ref,
        status="queued",
        progress="Job created, waiting to start...",
    )
    storage.save_job(analysis)

    background_tasks.add_task(_run_analysis, job_id, req)

    return {"job_id": job_id, "status": "queued"}
