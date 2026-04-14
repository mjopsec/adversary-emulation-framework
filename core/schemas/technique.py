"""Pydantic schemas untuk Technique."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict


Environment = Literal["it", "ot", "both"]
RiskLevel = Literal["low", "medium", "high", "critical"]


class TechniqueRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: str | None
    tactic: str
    tactics: list[str]
    environment: Environment
    is_subtechnique: bool
    parent_technique_id: str | None
    platforms: list[str]
    detection_note: str | None
    data_sources: list[str]
    mitigation_note: str | None
    risk_level: RiskLevel
    destructive: bool
    requires_explicit_approval: bool
    stix_id: str | None
    attack_url: str | None
    created_at: datetime
    updated_at: datetime
