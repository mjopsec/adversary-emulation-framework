"""
ORM Model: Execution — Catatan runtime eksekusi setiap langkah kampanye.
Setiap eksekusi teknik menghasilkan satu record Execution.
"""

import json
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import DateTime, Float, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.database import Base

if TYPE_CHECKING:
    from core.models.campaign import Campaign, CampaignStep
    from core.models.finding import Finding


class Execution(Base):
    __tablename__ = "executions"

    # ─── Primary Key ──────────────────────────────────────────────────────────
    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )

    # ─── Foreign Keys ─────────────────────────────────────────────────────────
    campaign_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("campaigns.id"), nullable=False, index=True
    )
    step_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("campaign_steps.id"), nullable=True
    )

    # ─── Target & Teknik ──────────────────────────────────────────────────────
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False)
    technique_name: Mapped[str | None] = mapped_column(String(500))
    # Host atau sistem yang ditarget dalam eksekusi ini
    target: Mapped[str | None] = mapped_column(String(500))

    # ─── Status ───────────────────────────────────────────────────────────────
    # pending | running | success | failed | partial | aborted | skipped
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending", index=True)

    # ─── Hasil Eksekusi ───────────────────────────────────────────────────────
    result_detail: Mapped[str | None] = mapped_column(Text)
    error_message: Mapped[str | None] = mapped_column(Text)

    # Daftar artefak yang ditinggalkan di sistem target (untuk cleanup)
    # Disimpan sebagai JSON array of strings
    _artifacts_created: Mapped[str | None] = mapped_column("artifacts_created", Text)

    # ─── AI Decision Log ──────────────────────────────────────────────────────
    # Log penalaran AI sebelum dan sesudah eksekusi (JSON)
    _ai_decision_log: Mapped[str | None] = mapped_column("ai_decision_log", Text)

    # ─── Timing ───────────────────────────────────────────────────────────────
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    duration_seconds: Mapped[float | None] = mapped_column(Float)

    # ─── Timestamps ───────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    # ─── Relationships ────────────────────────────────────────────────────────
    campaign: Mapped["Campaign"] = relationship("Campaign", back_populates="executions")
    step: Mapped["CampaignStep | None"] = relationship("CampaignStep")
    findings: Mapped[list["Finding"]] = relationship(
        "Finding", back_populates="execution", cascade="all, delete-orphan"
    )

    # ─── Property Helpers ─────────────────────────────────────────────────────
    @property
    def artifacts_created(self) -> list[str]:
        return json.loads(self._artifacts_created or "[]")

    @artifacts_created.setter
    def artifacts_created(self, value: list[str]) -> None:
        self._artifacts_created = json.dumps(value)

    @property
    def ai_decision_log(self) -> dict:
        return json.loads(self._ai_decision_log or "{}")

    @ai_decision_log.setter
    def ai_decision_log(self, value: dict) -> None:
        self._ai_decision_log = json.dumps(value)

    @property
    def is_terminal(self) -> bool:
        """Apakah eksekusi sudah selesai (tidak bisa berubah status lagi)."""
        return self.status in {"success", "failed", "aborted", "skipped"}

    def compute_duration(self) -> float | None:
        """Hitung durasi eksekusi jika sudah selesai."""
        if self.started_at and self.completed_at:
            delta = self.completed_at - self.started_at
            return delta.total_seconds()
        return None

    def __repr__(self) -> str:
        return (
            f"<Execution id={self.id!r} technique={self.technique_id!r} "
            f"target={self.target!r} status={self.status!r}>"
        )
