from __future__ import annotations

from pydantic import BaseModel, Field

from app.models.contract_info import ContractInfo
from app.models.function_info import FunctionInfo
from app.models.risk_flag import RiskFlag
from app.models.fund_flow import FundFlowGraph
from app.models.attack_surface import InvariantReport
from app.models.attack_path import AttackSurfaceReport


class AnalyzeRequest(BaseModel):
    repo_url: str
    ref: str = "main"
    docs_url: str = ""
    scope_notes: str = ""


class RepoAnalysis(BaseModel):
    job_id: str = ""
    repo_url: str = ""
    ref: str = ""
    commit: str = ""
    status: str = "queued"
    progress: str = ""
    files_scanned: int = 0
    solidity_files: int = 0
    language_mix: dict[str, int] = Field(default_factory=dict)
    contracts: list[ContractInfo] = Field(default_factory=list)
    functions: list[FunctionInfo] = Field(default_factory=list)
    risk_flags: list[RiskFlag] = Field(default_factory=list)
    fund_flows: FundFlowGraph = Field(default_factory=FundFlowGraph)
    invariants: InvariantReport = Field(default_factory=InvariantReport)
    attack_surface: AttackSurfaceReport = Field(default_factory=AttackSurfaceReport)
    notes: list[str] = Field(default_factory=list)
    error: str = ""
