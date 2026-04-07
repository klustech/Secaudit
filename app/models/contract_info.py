from __future__ import annotations

from pydantic import BaseModel, Field


class ContractInfo(BaseModel):
    name: str = ""
    file_path: str = ""
    kind: str = "contract"  # contract | interface | library | abstract
    inherits: list[str] = Field(default_factory=list)
    imports: list[str] = Field(default_factory=list)
    functions: list[str] = Field(default_factory=list)
    state_vars: list[str] = Field(default_factory=list)
    events: list[str] = Field(default_factory=list)
    modifiers: list[str] = Field(default_factory=list)
    custom_errors: list[str] = Field(default_factory=list)
    ai_summary: str = ""
    review_priority: str = "medium"
