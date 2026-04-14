"""Pydantic schemas untuk Campaign dan CampaignStep."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


EngagementType = Literal["blackbox", "greybox", "whitebox"]
EnvironmentType = Literal["it", "ot", "hybrid", "cloud", "hybrid_it_ot"]
CampaignStatus = Literal["draft", "validating", "active", "paused", "completed", "aborted"]
StepStatus = Literal["pending", "skipped", "in_progress", "completed", "failed"]
RiskLevel = Literal["low", "medium", "high", "critical"]


class CampaignBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    client_name: str = Field(..., min_length=1, max_length=255)
    engagement_type: EngagementType
    environment_type: EnvironmentType
    target_ips: list[str] = Field(default_factory=list)
    target_domains: list[str] = Field(default_factory=list)
    excluded_targets: list[str] = Field(default_factory=list)
    rules_of_engagement: str | None = None
    emergency_contact: str | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None
    objectives: list[str] = Field(default_factory=list)
    production_safe_mode: bool = True


class CampaignCreate(CampaignBase):
    apt_profile_id: str | None = None

    @model_validator(mode="after")
    def validate_scope(self) -> "CampaignCreate":
        if not self.target_ips and not self.target_domains:
            raise ValueError(
                "Scope tidak boleh kosong: isi minimal satu dari target_ips atau target_domains."
            )
        return self

    @model_validator(mode="after")
    def validate_roe(self) -> "CampaignCreate":
        if not self.rules_of_engagement:
            raise ValueError(
                "Rules of Engagement wajib diisi sebelum kampanye dapat dibuat."
            )
        return self


class CampaignUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None
    rules_of_engagement: str | None = None
    emergency_contact: str | None = None
    objectives: list[str] | None = None
    production_safe_mode: bool | None = None
    apt_profile_id: str | None = None


class CampaignRead(CampaignBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: CampaignStatus
    apt_profile_id: str | None
    context_validated: bool
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


# ─── CampaignStep Schemas ─────────────────────────────────────────────────────

class CampaignStepBase(BaseModel):
    order_index: int = Field(..., ge=0)
    phase: str = Field(..., min_length=1, max_length=100)
    technique_id: str = Field(..., pattern=r"^T\d{4}(\.\d{3})?$")
    method: str | None = None
    success_condition: str | None = None
    fallback_action: str | None = None
    notes: str | None = None
    risk_assessment: RiskLevel = "medium"


class CampaignStepCreate(CampaignStepBase):
    pass


class CampaignStepRead(CampaignStepBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    campaign_id: str
    ai_reasoning: str | None
    estimated_success_rate: float | None
    status: StepStatus
    created_at: datetime
