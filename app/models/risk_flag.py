from __future__ import annotations

from pydantic import BaseModel, Field


class RiskFlag(BaseModel):
    severity: str = "low"  # low | medium | high | critical
    category: str = ""
    file_path: str = ""
    contract: str = ""
    function: str = ""
    evidence: str = ""
    explanation: str = ""
    source: str = "heuristic"  # heuristic | parsed_fact | ai_summary
    manual_validation: list[str] = Field(default_factory=list)
