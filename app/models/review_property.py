"""Review property — an expected property that should be verified for a contract."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ReviewProperty(BaseModel):
    """A property that a human reviewer should verify."""
    kind: Literal[
        "balance", "supply", "access", "ordering",
        "initialization", "configuration", "oracle", "signature", "state",
    ] = "state"
    statement: str = ""
    rationale: str = ""
    related_functions: list[str] = Field(default_factory=list)
    confidence: Literal["low", "medium", "high"] = "medium"
    manual_checks: list[str] = Field(default_factory=list)
    # Provenance fields
    source_type: Literal[
        "parsed_fact", "heuristic_flag", "ai_review_note",
    ] = "heuristic_flag"
    confidence_basis: str = ""
    evidence_refs: list[str] = Field(default_factory=list)


class PropertyChecklistReport(BaseModel):
    """All review properties for a repo analysis."""
    properties: list[ReviewProperty] = Field(default_factory=list)
    summary: list[str] = Field(default_factory=list)
