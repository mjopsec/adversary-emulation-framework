"""
ORM Model: Technique — Katalog teknik serangan berbasis MITRE ATT&CK.
Mendukung Enterprise ATT&CK (IT) dan ICS ATT&CK (OT).
"""

import json
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.database import Base

if TYPE_CHECKING:
    from core.models.campaign import CampaignStep


class Technique(Base):
    __tablename__ = "techniques"

    # ─── Primary Key ──────────────────────────────────────────────────────────
    # Menggunakan ATT&CK ID langsung sebagai PK, contoh: "T1566" atau "T1566.001"
    id: Mapped[str] = mapped_column(String(20), primary_key=True)

    # ─── Identitas ────────────────────────────────────────────────────────────
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    # ─── Klasifikasi ATT&CK ───────────────────────────────────────────────────
    # Taktik utama teknik ini (initial_access, execution, persistence, dll.)
    tactic: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    # Semua taktik yang relevan (beberapa teknik ada di beberapa taktik)
    _tactics: Mapped[str | None] = mapped_column("tactics", Text)

    # it | ot | both
    environment: Mapped[str] = mapped_column(String(10), default="it", index=True)

    # Apakah ini sub-teknik (contoh: T1566.001 adalah sub dari T1566)
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False)
    parent_technique_id: Mapped[str | None] = mapped_column(
        String(20), ForeignKey("techniques.id"), nullable=True
    )

    # ─── Platform ─────────────────────────────────────────────────────────────
    # Disimpan sebagai JSON array, contoh: '["Windows", "Linux", "macOS"]'
    _platforms: Mapped[str | None] = mapped_column("platforms", Text)

    # ─── Detection & Mitigation ───────────────────────────────────────────────
    detection_note: Mapped[str | None] = mapped_column(Text)
    _data_sources: Mapped[str | None] = mapped_column("data_sources", Text)
    mitigation_note: Mapped[str | None] = mapped_column(Text)

    # ─── Risk Assessment ──────────────────────────────────────────────────────
    # low | medium | high | critical
    risk_level: Mapped[str] = mapped_column(String(20), default="medium")
    # Apakah teknik ini berpotensi merusak sistem (khusus OT)
    destructive: Mapped[bool] = mapped_column(Boolean, default=False)
    # Apakah teknik ini memerlukan persetujuan khusus sebelum dieksekusi
    requires_explicit_approval: Mapped[bool] = mapped_column(Boolean, default=False)

    # ─── STIX Reference ───────────────────────────────────────────────────────
    stix_id: Mapped[str | None] = mapped_column(String(100), unique=True)
    attack_url: Mapped[str | None] = mapped_column(String(500))

    # ─── Timestamps ───────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # ─── Relationships ────────────────────────────────────────────────────────
    subtechniques: Mapped[list["Technique"]] = relationship(
        "Technique",
        foreign_keys=[parent_technique_id],
        back_populates="parent_technique",
    )
    parent_technique: Mapped["Technique | None"] = relationship(
        "Technique",
        foreign_keys=[parent_technique_id],
        back_populates="subtechniques",
        remote_side="Technique.id",
    )
    campaign_steps: Mapped[list["CampaignStep"]] = relationship(
        "CampaignStep", back_populates="technique"
    )

    # ─── Property Helpers ─────────────────────────────────────────────────────
    @property
    def platforms(self) -> list[str]:
        return json.loads(self._platforms or "[]")

    @platforms.setter
    def platforms(self, value: list[str]) -> None:
        self._platforms = json.dumps(value)

    @property
    def tactics(self) -> list[str]:
        return json.loads(self._tactics or "[]")

    @tactics.setter
    def tactics(self, value: list[str]) -> None:
        self._tactics = json.dumps(value)

    @property
    def data_sources(self) -> list[str]:
        return json.loads(self._data_sources or "[]")

    @data_sources.setter
    def data_sources(self, value: list[str]) -> None:
        self._data_sources = json.dumps(value)

    def __repr__(self) -> str:
        return f"<Technique id={self.id!r} name={self.name!r} env={self.environment!r}>"
