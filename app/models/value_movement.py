"""Value movement edge — represents a single value flow for manual review."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ValueMovementEdge(BaseModel):
    """A directed value movement edge for audit review.

    Describes how value enters, moves through, or exits a contract.
    """
    contract: str = ""
    function: str = ""
    direction: Literal["inflow", "internal", "outflow", "approval"] = "outflow"
    asset_type: Literal["eth", "erc20", "erc721", "erc1155", "unknown"] = "unknown"
    mechanism: str = ""
    source_hint: str | None = None
    destination_hint: str | None = None
    caller_influenced: bool = False
    access_controlled: bool = False
    external_interaction: bool = False
    notes: list[str] = Field(default_factory=list)
    manual_checks: list[str] = Field(default_factory=list)


class ValueMovementReport(BaseModel):
    """All value movement edges for a repo analysis."""
    edges: list[ValueMovementEdge] = Field(default_factory=list)
    summary: list[str] = Field(default_factory=list)
