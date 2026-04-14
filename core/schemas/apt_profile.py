"""Pydantic schemas untuk APTProfile."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


Motivation = Literal["espionage", "financial", "hacktivist", "sabotage", "unknown"]
Sophistication = Literal["low", "medium", "high", "nation_state"]


class APTProfileBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    mitre_group_id: str | None = Field(None, pattern=r"^G\d{4}$")
    motivation: Motivation
    sophistication: Sophistication
    technique_preferences: list[str] = Field(default_factory=list)
    preferred_tools: list[str] = Field(default_factory=list)
    known_aliases: list[str] = Field(default_factory=list)
    targets_ot: bool = False
    is_custom: bool = True
    attributed_country: str | None = None


class APTProfileCreate(APTProfileBase):
    pass


class APTProfileUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None
    motivation: Motivation | None = None
    sophistication: Sophistication | None = None
    technique_preferences: list[str] | None = None
    preferred_tools: list[str] | None = None
    targets_ot: bool | None = None
    attributed_country: str | None = None


class APTProfileRead(APTProfileBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    created_at: datetime
    updated_at: datetime
