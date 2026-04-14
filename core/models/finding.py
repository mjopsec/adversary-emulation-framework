"""
ORM Model: Finding — Temuan dari setiap eksekusi teknik.
Mencatat apakah teknik terdeteksi, gap apa yang ditemukan, dan rekomendasi.
"""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.database import Base

if TYPE_CHECKING:
    from core.models.campaign import Campaign
    from core.models.execution import Execution


class Finding(Base):
    __tablename__ = "findings"

    # ─── Primary Key ──────────────────────────────────────────────────────────
    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )

    # ─── Foreign Keys ─────────────────────────────────────────────────────────
    campaign_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("campaigns.id"), nullable=False, index=True
    )
    execution_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("executions.id"), nullable=True
    )

    # ─── Referensi Teknik ─────────────────────────────────────────────────────
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False)
    technique_name: Mapped[str | None] = mapped_column(String(500))

    # ─── Hasil Deteksi ────────────────────────────────────────────────────────
    # Apakah teknik ini terdeteksi oleh stack pertahanan?
    detected: Mapped[bool] = mapped_column(Boolean, default=False)
    # Berapa detik sampai terdeteksi? None = tidak terdeteksi
    detection_time_seconds: Mapped[float | None] = mapped_column(Float)
    # Rule/alert apa yang trigger
    triggered_rule: Mapped[str | None] = mapped_column(Text)
    # none | partial | full
    detection_quality: Mapped[str] = mapped_column(String(20), default="none")

    # ─── Severity & Gap ───────────────────────────────────────────────────────
    # critical | high | medium | low | informational
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    gap_description: Mapped[str | None] = mapped_column(Text)

    # ─── Rekomendasi Perbaikan ────────────────────────────────────────────────
    remediation_recommendation: Mapped[str | None] = mapped_column(Text)

    # Detection rules yang direkomendasikan (jika teknik tidak terdeteksi)
    sigma_rule: Mapped[str | None] = mapped_column(Text)
    kql_query: Mapped[str | None] = mapped_column(Text)
    spl_query: Mapped[str | None] = mapped_column(Text)  # Splunk SPL
    yara_rule: Mapped[str | None] = mapped_column(Text)

    # ─── False Positive Analysis ──────────────────────────────────────────────
    # Jika terdeteksi tapi dengan banyak false positive
    false_positive_prone: Mapped[bool] = mapped_column(Boolean, default=False)
    tuning_recommendation: Mapped[str | None] = mapped_column(Text)

    # ─── Timestamps ───────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    # ─── Relationships ────────────────────────────────────────────────────────
    campaign: Mapped["Campaign"] = relationship("Campaign", back_populates="findings")
    execution: Mapped["Execution | None"] = relationship(
        "Execution", back_populates="findings"
    )

    @property
    def is_gap(self) -> bool:
        """True jika ini adalah detection gap (tidak terdeteksi sama sekali)."""
        return not self.detected and self.detection_quality == "none"

    @property
    def priority_score(self) -> int:
        """
        Skor prioritas untuk remediation (semakin tinggi = semakin urgent).
        Berdasarkan: severity × (1 jika gap, 0.5 jika partial)
        """
        severity_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
        base = severity_weight.get(self.severity, 0)
        if self.is_gap:
            return base * 2
        elif self.detection_quality == "partial":
            return base
        return 0

    def __repr__(self) -> str:
        return (
            f"<Finding technique={self.technique_id!r} "
            f"detected={self.detected} severity={self.severity!r}>"
        )
