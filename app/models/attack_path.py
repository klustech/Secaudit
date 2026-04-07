"""AttackPath — a safe, non-exploitative reasoning chain about potential risk."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AttackPath(BaseModel):
    """A hypothetical risk scenario — NOT an exploit, but a reasoning chain.

    Describes: IF condition X fails THEN consequence Y is possible.
    """
    id: str = ""
    title: str = ""
    severity: str = "medium"  # low, medium, high, critical
    preconditions: list[str] = Field(default_factory=list)  # what must be true for risk
    affected_functions: list[str] = Field(default_factory=list)
    affected_contracts: list[str] = Field(default_factory=list)
    risk_category: str = ""  # reentrancy, access-bypass, drain, manipulation, dos, replay
    consequence: str = ""    # what could happen
    likelihood: str = "requires-validation"  # requires-validation, possible, unlikely
    evidence: list[str] = Field(default_factory=list)
    why_concerning: str = ""
    what_prevents_it: str = ""  # existing mitigations found
    validation_steps: list[str] = Field(default_factory=list)
    related_flags: list[str] = Field(default_factory=list)  # risk flag references


class AttackSurfaceReport(BaseModel):
    """Complete attack surface analysis."""
    paths: list[AttackPath] = Field(default_factory=list)
    critical_paths: int = 0
    high_paths: int = 0
    summary: str = ""
