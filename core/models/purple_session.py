"""
ORM Models: PurpleSession dan PurpleEvent.

PurpleSession adalah sesi latihan Purple Team — di mana red team dan blue team
bekerja bersama untuk menguji dan memperbaiki kemampuan deteksi.

Lifecycle:
  PurpleSession: draft → active → completed
  PurpleEvent:   red_team_action → blue_team_response → gap_identified | covered

Setiap event mencatat satu siklus:
1. Red team mengeksekusi teknik
2. Blue team merespons (detected? blocked? missed?)
3. Sistem menghitung coverage gap
4. Rekomendasi deteksi di-generate
"""

import json
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.database import Base

if TYPE_CHECKING:
    from core.models.campaign import Campaign


class PurpleSession(Base):
    """Sesi Purple Team — kolaborasi red dan blue team."""

    __tablename__ = "purple_sessions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )

    # ─── Relasi ke Kampanye ───────────────────────────────────────────────────
    campaign_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("campaigns.id"), nullable=True
    )

    # ─── Metadata Sesi ────────────────────────────────────────────────────────
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    environment: Mapped[str] = mapped_column(String(20), default="it")  # it | ot

    # ─── Partisipan ───────────────────────────────────────────────────────────
    red_team_lead: Mapped[str | None] = mapped_column(String(255))
    blue_team_lead: Mapped[str | None] = mapped_column(String(255))
    facilitator: Mapped[str | None] = mapped_column(String(255))

    # ─── Status ───────────────────────────────────────────────────────────────
    # draft | active | paused | completed
    status: Mapped[str] = mapped_column(String(20), default="draft", index=True)

    # ─── Metrik Coverage ──────────────────────────────────────────────────────
    # Dihitung ulang setiap kali ada event baru
    total_techniques_tested: Mapped[int] = mapped_column(Integer, default=0)
    techniques_detected: Mapped[int] = mapped_column(Integer, default=0)
    techniques_missed: Mapped[int] = mapped_column(Integer, default=0)
    techniques_blocked: Mapped[int] = mapped_column(Integer, default=0)
    # detection_coverage = techniques_detected / total_techniques_tested
    detection_coverage: Mapped[float] = mapped_column(Float, default=0.0)

    # ─── Timestamps ───────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)

    # ─── Relationships ────────────────────────────────────────────────────────
    campaign: Mapped["Campaign | None"] = relationship("Campaign")
    events: Mapped[list["PurpleEvent"]] = relationship(
        "PurpleEvent",
        back_populates="session",
        order_by="PurpleEvent.created_at",
        cascade="all, delete-orphan",
    )

    # ─── Properties ───────────────────────────────────────────────────────────
    @property
    def is_active(self) -> bool:
        return self.status == "active"

    @property
    def gap_count(self) -> int:
        return self.techniques_missed

    def recompute_metrics(self) -> None:
        """Hitung ulang metrik dari events. Panggil setelah menambah event."""
        detected = sum(1 for e in self.events if e.blue_response == "detected")
        blocked = sum(1 for e in self.events if e.blue_response == "blocked")
        missed = sum(1 for e in self.events if e.blue_response == "missed")
        total = len(self.events)

        self.total_techniques_tested = total
        self.techniques_detected = detected
        self.techniques_blocked = blocked
        self.techniques_missed = missed
        self.detection_coverage = round(
            (detected + blocked) / total, 3
        ) if total > 0 else 0.0

    def to_summary(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "environment": self.environment,
            "status": self.status,
            "campaign_id": self.campaign_id,
            "total_tested": self.total_techniques_tested,
            "detected": self.techniques_detected,
            "blocked": self.techniques_blocked,
            "missed": self.techniques_missed,
            "detection_coverage": self.detection_coverage,
            "gap_count": self.gap_count,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

    def __repr__(self) -> str:
        return (
            f"<PurpleSession name={self.name!r} status={self.status!r} "
            f"coverage={self.detection_coverage:.0%}>"
        )


class PurpleEvent(Base):
    """
    Satu siklus red-blue dalam Purple Team session.

    Red team → eksekusi teknik
    Blue team → merespons (detected / blocked / missed / false_positive)
    """

    __tablename__ = "purple_events"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )

    session_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("purple_sessions.id"), nullable=False, index=True
    )

    # ─── Red Team Action ──────────────────────────────────────────────────────
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False)
    technique_name: Mapped[str | None] = mapped_column(String(500))
    tactic: Mapped[str | None] = mapped_column(String(100))
    execution_method: Mapped[str | None] = mapped_column(String(255))
    target: Mapped[str | None] = mapped_column(String(255))
    red_notes: Mapped[str | None] = mapped_column(Text)

    # ─── Blue Team Response ───────────────────────────────────────────────────
    # detected | blocked | missed | false_positive | partial
    blue_response: Mapped[str | None] = mapped_column(String(30))
    # Waktu deteksi (detik setelah eksekusi) — None jika tidak terdeteksi
    detection_latency_seconds: Mapped[float | None] = mapped_column(Float)
    # Tool/sistem yang mendeteksi (SIEM, EDR, Firewall, dll.)
    detected_by: Mapped[str | None] = mapped_column(String(255))
    # Alert/rule yang trigger
    triggered_alert: Mapped[str | None] = mapped_column(Text)
    blue_notes: Mapped[str | None] = mapped_column(Text)

    # ─── Gap Analysis ─────────────────────────────────────────────────────────
    is_gap: Mapped[bool] = mapped_column(Boolean, default=False)
    gap_severity: Mapped[str | None] = mapped_column(String(20))   # critical|high|medium|low
    gap_description: Mapped[str | None] = mapped_column(Text)

    # ─── Rekomendasi ──────────────────────────────────────────────────────────
    sigma_rule_hint: Mapped[str | None] = mapped_column(Text)
    remediation_priority: Mapped[int] = mapped_column(Integer, default=5)  # 1=urgent, 10=low
    _remediation_steps: Mapped[str | None] = mapped_column("remediation_steps", Text)

    # ─── Timestamps ───────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    # ─── Relationships ────────────────────────────────────────────────────────
    session: Mapped["PurpleSession"] = relationship("PurpleSession", back_populates="events")

    # ─── Properties ───────────────────────────────────────────────────────────
    @property
    def remediation_steps(self) -> list[str]:
        return json.loads(self._remediation_steps or "[]")

    @remediation_steps.setter
    def remediation_steps(self, value: list[str]) -> None:
        self._remediation_steps = json.dumps(value)

    @property
    def was_detected(self) -> bool:
        return self.blue_response in ("detected", "blocked")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "execution_method": self.execution_method,
            "target": self.target,
            "blue_response": self.blue_response,
            "detection_latency_seconds": self.detection_latency_seconds,
            "detected_by": self.detected_by,
            "triggered_alert": self.triggered_alert,
            "is_gap": self.is_gap,
            "gap_severity": self.gap_severity,
            "gap_description": self.gap_description,
            "sigma_rule_hint": self.sigma_rule_hint,
            "remediation_priority": self.remediation_priority,
            "remediation_steps": self.remediation_steps,
            "red_notes": self.red_notes,
            "blue_notes": self.blue_notes,
        }

    def __repr__(self) -> str:
        return (
            f"<PurpleEvent technique={self.technique_id!r} "
            f"response={self.blue_response!r} gap={self.is_gap}>"
        )
