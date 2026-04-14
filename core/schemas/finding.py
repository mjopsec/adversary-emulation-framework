"""Pydantic schemas untuk Finding."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


DetectionQuality = Literal["none", "partial", "full"]
Severity = Literal["critical", "high", "medium", "low", "informational"]


class FindingCreate(BaseModel):
    campaign_id: str
    execution_id: str | None = None
    technique_id: str
    technique_name: str | None = None
    detected: bool = False
    detection_time_seconds: float | None = None
    triggered_rule: str | None = None
    detection_quality: DetectionQuality = "none"
    severity: Severity
    gap_description: str | None = None
    remediation_recommendation: str | None = None
    sigma_rule: str | None = None
    kql_query: str | None = None
    spl_query: str | None = None
    yara_rule: str | None = None
    false_positive_prone: bool = False
    tuning_recommendation: str | None = None


class FindingRead(FindingCreate):
    model_config = ConfigDict(from_attributes=True)

    id: str
    is_gap: bool
    priority_score: int
    created_at: datetime
