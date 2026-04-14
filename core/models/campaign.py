"""
ORM Models: Campaign dan CampaignStep.
Campaign adalah unit utama engagement; CampaignStep adalah langkah individual.
"""

import json
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.database import Base

if TYPE_CHECKING:
    from core.models.apt_profile import APTProfile
    from core.models.execution import Execution
    from core.models.finding import Finding
    from core.models.technique import Technique


class Campaign(Base):
    __tablename__ = "campaigns"

    # ─── Primary Key ──────────────────────────────────────────────────────────
    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )

    # ─── Metadata Engagement ──────────────────────────────────────────────────
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    client_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # blackbox | greybox | whitebox
    engagement_type: Mapped[str] = mapped_column(String(20), nullable=False)
    # it | ot | hybrid | cloud | hybrid_it_ot
    environment_type: Mapped[str] = mapped_column(String(20), nullable=False)

    # ─── Scope ────────────────────────────────────────────────────────────────
    # Disimpan sebagai JSON arrays
    _target_ips: Mapped[str | None] = mapped_column("target_ips", Text)
    _target_domains: Mapped[str | None] = mapped_column("target_domains", Text)
    _excluded_targets: Mapped[str | None] = mapped_column("excluded_targets", Text)

    # ─── Rules of Engagement ──────────────────────────────────────────────────
    rules_of_engagement: Mapped[str | None] = mapped_column(Text)
    emergency_contact: Mapped[str | None] = mapped_column(String(500))

    # ─── Jadwal Engagement ────────────────────────────────────────────────────
    start_date: Mapped[datetime | None] = mapped_column(DateTime)
    end_date: Mapped[datetime | None] = mapped_column(DateTime)

    # ─── Status ───────────────────────────────────────────────────────────────
    # draft | validating | active | paused | completed | aborted
    status: Mapped[str] = mapped_column(String(20), default="draft", index=True)

    # ─── APT Profile ──────────────────────────────────────────────────────────
    apt_profile_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("apt_profiles.id"), nullable=True
    )

    # ─── Tujuan Kampanye ──────────────────────────────────────────────────────
    # JSON array of strings, contoh: ["gain_initial_access", "lateral_movement"]
    _objectives: Mapped[str | None] = mapped_column("objectives", Text)

    # ─── Mode Produksi ────────────────────────────────────────────────────────
    # Jika True, operasi write ke OT diblokir
    production_safe_mode: Mapped[bool] = mapped_column(Boolean, default=True)
    # Jika True, AI sudah memvalidasi kelengkapan engagement context
    context_validated: Mapped[bool] = mapped_column(Boolean, default=False)

    # ─── Timestamps ───────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)

    # ─── Relationships ────────────────────────────────────────────────────────
    apt_profile: Mapped["APTProfile | None"] = relationship(
        "APTProfile", back_populates="campaigns"
    )
    steps: Mapped[list["CampaignStep"]] = relationship(
        "CampaignStep",
        back_populates="campaign",
        order_by="CampaignStep.order_index",
        cascade="all, delete-orphan",
    )
    executions: Mapped[list["Execution"]] = relationship(
        "Execution", back_populates="campaign", cascade="all, delete-orphan"
    )
    findings: Mapped[list["Finding"]] = relationship(
        "Finding", back_populates="campaign", cascade="all, delete-orphan"
    )

    # ─── Property Helpers ─────────────────────────────────────────────────────
    @property
    def target_ips(self) -> list[str]:
        return json.loads(self._target_ips or "[]")

    @target_ips.setter
    def target_ips(self, value: list[str]) -> None:
        self._target_ips = json.dumps(value)

    @property
    def target_domains(self) -> list[str]:
        return json.loads(self._target_domains or "[]")

    @target_domains.setter
    def target_domains(self, value: list[str]) -> None:
        self._target_domains = json.dumps(value)

    @property
    def excluded_targets(self) -> list[str]:
        return json.loads(self._excluded_targets or "[]")

    @excluded_targets.setter
    def excluded_targets(self, value: list[str]) -> None:
        self._excluded_targets = json.dumps(value)

    @property
    def objectives(self) -> list[str]:
        return json.loads(self._objectives or "[]")

    @objectives.setter
    def objectives(self, value: list[str]) -> None:
        self._objectives = json.dumps(value)

    @property
    def is_active(self) -> bool:
        return self.status == "active"

    @property
    def scope_defined(self) -> bool:
        return bool(self.target_ips or self.target_domains)

    def __repr__(self) -> str:
        return (
            f"<Campaign id={self.id!r} name={self.name!r} "
            f"client={self.client_name!r} status={self.status!r}>"
        )


class CampaignStep(Base):
    __tablename__ = "campaign_steps"

    # ─── Primary Key ──────────────────────────────────────────────────────────
    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )

    # ─── Foreign Keys ─────────────────────────────────────────────────────────
    campaign_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("campaigns.id"), nullable=False, index=True
    )
    technique_id: Mapped[str] = mapped_column(
        String(20), ForeignKey("techniques.id"), nullable=False
    )

    # ─── Urutan dan Fase ──────────────────────────────────────────────────────
    order_index: Mapped[int] = mapped_column(Integer, nullable=False)
    # Nama taktik ATT&CK, contoh: "initial_access", "lateral_movement"
    phase: Mapped[str] = mapped_column(String(100), nullable=False)

    # ─── Detail Eksekusi ──────────────────────────────────────────────────────
    # Implementasi spesifik dari teknik ini (contoh: metode PowerShell konkret)
    method: Mapped[str | None] = mapped_column(Text)
    success_condition: Mapped[str | None] = mapped_column(Text)
    fallback_action: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)

    # ─── AI Context ───────────────────────────────────────────────────────────
    # Penjelasan dari AI mengapa langkah ini dipilih
    ai_reasoning: Mapped[str | None] = mapped_column(Text)
    # low | medium | high | critical
    risk_assessment: Mapped[str] = mapped_column(String(20), default="medium")
    # Estimasi probabilitas sukses (0.0 - 1.0)
    estimated_success_rate: Mapped[float | None] = mapped_column()

    # ─── Status ───────────────────────────────────────────────────────────────
    # pending | skipped | in_progress | completed | failed
    status: Mapped[str] = mapped_column(String(20), default="pending")

    # ─── Timestamps ───────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    # ─── Relationships ────────────────────────────────────────────────────────
    campaign: Mapped["Campaign"] = relationship("Campaign", back_populates="steps")
    technique: Mapped["Technique"] = relationship(
        "Technique", back_populates="campaign_steps"
    )

    def __repr__(self) -> str:
        return (
            f"<CampaignStep order={self.order_index} "
            f"technique={self.technique_id!r} phase={self.phase!r}>"
        )
