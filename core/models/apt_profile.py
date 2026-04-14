"""
ORM Model: APTProfile — Profil adversari yang disimulasikan.
Mencakup kelompok APT yang dikenal maupun persona custom.
"""

import json
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.database import Base

if TYPE_CHECKING:
    from core.models.campaign import Campaign


class APTProfile(Base):
    __tablename__ = "apt_profiles"

    # ─── Primary Key ──────────────────────────────────────────────────────────
    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )

    # ─── Identitas ────────────────────────────────────────────────────────────
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text)

    # ID grup MITRE ATT&CK jika ada (contoh: "G0016" untuk APT29)
    mitre_group_id: Mapped[str | None] = mapped_column(String(20), index=True)

    # ─── Karakteristik Adversari ──────────────────────────────────────────────
    # espionage | financial | hacktivist | sabotage | unknown
    motivation: Mapped[str] = mapped_column(String(50), nullable=False)
    # low | medium | high | nation_state
    sophistication: Mapped[str] = mapped_column(String(50), nullable=False)

    # Disimpan sebagai JSON array string, contoh: '["T1566", "T1078"]'
    _technique_preferences: Mapped[str | None] = mapped_column(
        "technique_preferences", Text
    )
    _preferred_tools: Mapped[str | None] = mapped_column("preferred_tools", Text)
    _known_aliases: Mapped[str | None] = mapped_column("known_aliases", Text)

    # Apakah kelompok ini diketahui menarget lingkungan OT/ICS
    targets_ot: Mapped[bool] = mapped_column(Boolean, default=False)
    # Apakah ini profil custom (bukan dari MITRE ATT&CK)
    is_custom: Mapped[bool] = mapped_column(Boolean, default=True)

    # ─── Origin ───────────────────────────────────────────────────────────────
    # Negara/region asal jika diketahui (untuk konteks engagement)
    attributed_country: Mapped[str | None] = mapped_column(String(100))

    # ─── Timestamps ───────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # ─── Relationships ────────────────────────────────────────────────────────
    campaigns: Mapped[list["Campaign"]] = relationship(
        "Campaign", back_populates="apt_profile"
    )

    # ─── Property Helpers (JSON serialization) ────────────────────────────────
    @property
    def technique_preferences(self) -> list[str]:
        return json.loads(self._technique_preferences or "[]")

    @technique_preferences.setter
    def technique_preferences(self, value: list[str]) -> None:
        self._technique_preferences = json.dumps(value)

    @property
    def preferred_tools(self) -> list[str]:
        return json.loads(self._preferred_tools or "[]")

    @preferred_tools.setter
    def preferred_tools(self, value: list[str]) -> None:
        self._preferred_tools = json.dumps(value)

    @property
    def known_aliases(self) -> list[str]:
        return json.loads(self._known_aliases or "[]")

    @known_aliases.setter
    def known_aliases(self, value: list[str]) -> None:
        self._known_aliases = json.dumps(value)

    def __repr__(self) -> str:
        return f"<APTProfile name={self.name!r} motivation={self.motivation!r}>"
