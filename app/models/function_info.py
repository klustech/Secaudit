from __future__ import annotations

from pydantic import BaseModel, Field


class FunctionInfo(BaseModel):
    contract: str = ""
    file_path: str = ""
    name: str = ""
    signature: str = ""
    visibility: str = ""
    mutability: str = ""
    modifiers: list[str] = Field(default_factory=list)
    writes_state: bool = False
    external_calls: list[str] = Field(default_factory=list)
    token_actions: list[str] = Field(default_factory=list)
    risk_tags: list[str] = Field(default_factory=list)
    source: str = ""
    ai_summary: str = ""
    manual_checks: list[str] = Field(default_factory=list)
