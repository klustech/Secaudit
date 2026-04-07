"""Risk scenario — a non-weaponized review scenario for manual validation."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class RiskScenario(BaseModel):
    """A non-weaponized risk scenario for manual review."""
    title: str = ""
    category: Literal[
        "authorization", "accounting", "external-interaction",
        "initialization", "upgradeability", "oracle", "signatures",
        "timelock", "availability", "configuration",
    ] = "authorization"
    risky_assumption: str = ""
    why_it_matters: str = ""
    affected_functions: list[str] = Field(default_factory=list)
    severity_hint: Literal["low", "medium", "high"] = "medium"
    manual_validation_steps: list[str] = Field(default_factory=list)
    remediation_themes: list[str] = Field(default_factory=list)


class RiskScenarioReport(BaseModel):
    """All risk scenarios for a repo analysis."""
    scenarios: list[RiskScenario] = Field(default_factory=list)
    summary: list[str] = Field(default_factory=list)
