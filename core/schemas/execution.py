"""Pydantic schemas untuk Execution."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


ExecutionStatus = Literal["pending", "running", "success", "failed", "partial", "aborted", "skipped"]


class ExecutionCreate(BaseModel):
    campaign_id: str
    step_id: str | None = None
    technique_id: str
    technique_name: str | None = None
    target: str | None = None


class ExecutionUpdate(BaseModel):
    status: ExecutionStatus | None = None
    result_detail: str | None = None
    error_message: str | None = None
    artifacts_created: list[str] | None = None
    ai_decision_log: dict | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_seconds: float | None = None


class ExecutionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    campaign_id: str
    step_id: str | None
    technique_id: str
    technique_name: str | None
    target: str | None
    status: ExecutionStatus
    result_detail: str | None
    error_message: str | None
    duration_seconds: float | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
