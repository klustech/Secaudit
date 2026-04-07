"""Invariant — an expected property that should hold for a contract."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Invariant(BaseModel):
    """A property that should always hold true for a contract."""
    contract: str = ""
    description: str = ""
    kind: str = ""  # balance, access, state, ordering, supply
    confidence: str = "medium"  # low, medium, high
    source: str = "inferred"  # inferred, parsed_fact
    threatened_by: list[str] = Field(default_factory=list)  # function names that could break it
    evidence: str = ""
    manual_checks: list[str] = Field(default_factory=list)


class InvariantReport(BaseModel):
    """All invariants for a repo analysis."""
    invariants: list[Invariant] = Field(default_factory=list)
    broken_invariant_count: int = 0
    summary: str = ""
