"""Fund flow edge — represents a single token/ETH movement path."""

from __future__ import annotations

from pydantic import BaseModel, Field


class FundFlowEdge(BaseModel):
    """A directed edge in the fund flow graph.

    Represents: source_contract.source_function -> sink_contract.sink_function
    with value moving through a specific mechanism.
    """
    source_contract: str = ""
    source_function: str = ""
    sink_contract: str = ""
    sink_function: str = ""
    file_path: str = ""
    mechanism: str = ""          # transfer, call{value}, approve+transferFrom, etc.
    token: str = ""              # ETH, ERC20, specific token var name
    sender: str = ""             # msg.sender, address(this), parameter name
    recipient: str = ""          # msg.sender, owner, arbitrary param, etc.
    amount_source: str = ""      # literal, parameter, state var, computed
    guarded: bool = False        # has access control
    guard_details: str = ""      # which modifier/require
    reentrancy_safe: bool = False
    evidence: str = ""


class FundFlowGraph(BaseModel):
    """Complete fund flow analysis for a repo."""
    edges: list[FundFlowEdge] = Field(default_factory=list)
    entry_points: list[str] = Field(default_factory=list)   # functions where value enters
    exit_points: list[str] = Field(default_factory=list)     # functions where value leaves
    internal_moves: list[str] = Field(default_factory=list)  # internal accounting transfers
    unguarded_exits: list[str] = Field(default_factory=list) # exit points with no access control
    summary: str = ""
