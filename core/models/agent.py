"""
ORM Models: Agent dan AgentTask.

Agent merepresentasikan implant yang di-deploy ke sistem target.
AgentTask adalah antrian perintah yang dikirim ke agent.

Lifecycle agent:
  registered → active (saat pertama check-in) → stale (tidak check-in lama) → terminated

Lifecycle task:
  pending → assigned (agent ambil) → running → completed | failed | timeout
"""

import json
import secrets
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.database import Base

if TYPE_CHECKING:
    from core.models.campaign import Campaign


class Agent(Base):
    __tablename__ = "agents"

    # ─── Identity ─────────────────────────────────────────────────────────────
    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    # Token rahasia untuk autentikasi beacon (hex 32 byte)
    token: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False,
        default=lambda: secrets.token_hex(32),
    )

    # ─── Identitas Target ─────────────────────────────────────────────────────
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45))          # IPv4/IPv6
    # windows | linux | macos | rtu | plc | hmi | unknown
    os_type: Mapped[str] = mapped_column(String(50), default="unknown")
    os_version: Mapped[str | None] = mapped_column(String(255))
    arch: Mapped[str | None] = mapped_column(String(20))                # x64 | x86 | arm

    # ─── Tipe Agent ───────────────────────────────────────────────────────────
    # it | ot
    agent_type: Mapped[str] = mapped_column(String(10), default="it")
    # Nama implant/framework yang digunakan (contoh: "aep-agent-v1", "manual")
    agent_name: Mapped[str] = mapped_column(String(100), default="aep-agent")
    agent_version: Mapped[str | None] = mapped_column(String(50))

    # ─── Kapabilitas ──────────────────────────────────────────────────────────
    # JSON list kapabilitas: ["execute_cmd", "file_ops", "modbus", "dnp3", ...]
    _capabilities: Mapped[str | None] = mapped_column("capabilities", Text)
    # Privilege level agent saat ini: user | admin | system | root
    privilege_level: Mapped[str] = mapped_column(String(20), default="user")
    has_elevated: Mapped[bool] = mapped_column(Boolean, default=False)

    # ─── Kampanye & Scope ─────────────────────────────────────────────────────
    campaign_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("campaigns.id"), nullable=True
    )
    # OT-specific
    ot_protocol: Mapped[str | None] = mapped_column(String(50))         # modbus | dnp3 | opc_ua
    ot_zone: Mapped[str | None] = mapped_column(String(100))

    # ─── Status ───────────────────────────────────────────────────────────────
    # registered | active | stale | terminated
    status: Mapped[str] = mapped_column(String(20), default="registered", index=True)

    # ─── Beacon / Heartbeat ───────────────────────────────────────────────────
    beacon_interval_seconds: Mapped[int] = mapped_column(Integer, default=60)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime)
    check_in_count: Mapped[int] = mapped_column(Integer, default=0)

    # ─── Timestamps ───────────────────────────────────────────────────────────
    registered_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    terminated_at: Mapped[datetime | None] = mapped_column(DateTime)

    # ─── Metadata Tambahan ────────────────────────────────────────────────────
    # JSON dict: network interfaces, antivirus detected, edr presence, dll.
    _metadata_extra: Mapped[str | None] = mapped_column("metadata_extra", Text)
    notes: Mapped[str | None] = mapped_column(Text)

    # ─── Relationships ────────────────────────────────────────────────────────
    campaign: Mapped["Campaign | None"] = relationship("Campaign")
    tasks: Mapped[list["AgentTask"]] = relationship(
        "AgentTask",
        back_populates="agent",
        cascade="all, delete-orphan",
        order_by="AgentTask.created_at",
    )

    # ─── Properties ───────────────────────────────────────────────────────────
    @property
    def capabilities(self) -> list[str]:
        return json.loads(self._capabilities or "[]")

    @capabilities.setter
    def capabilities(self, value: list[str]) -> None:
        self._capabilities = json.dumps(value)

    @property
    def metadata_extra(self) -> dict:
        return json.loads(self._metadata_extra or "{}")

    @metadata_extra.setter
    def metadata_extra(self, value: dict) -> None:
        self._metadata_extra = json.dumps(value)

    @property
    def is_active(self) -> bool:
        return self.status == "active"

    @property
    def is_stale(self) -> bool:
        """Agent dianggap stale jika tidak check-in dalam 3x beacon interval."""
        if not self.last_seen:
            return False
        from datetime import timezone
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        elapsed = (now - self.last_seen).total_seconds()
        return elapsed > (self.beacon_interval_seconds * 3)

    def has_capability(self, cap: str) -> bool:
        return cap in self.capabilities

    def __repr__(self) -> str:
        return (
            f"<Agent id={self.id!r} host={self.hostname!r} "
            f"type={self.agent_type!r} status={self.status!r}>"
        )


class AgentTask(Base):
    __tablename__ = "agent_tasks"

    # ─── Identity ─────────────────────────────────────────────────────────────
    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )

    # ─── Foreign Keys ─────────────────────────────────────────────────────────
    agent_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("agents.id"), nullable=False, index=True
    )
    campaign_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("campaigns.id"), nullable=True
    )
    execution_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("executions.id"), nullable=True
    )

    # ─── Task Definition ──────────────────────────────────────────────────────
    # execute_technique | collect_info | cleanup | shell_command | custom
    task_type: Mapped[str] = mapped_column(String(50), nullable=False)
    technique_id: Mapped[str | None] = mapped_column(String(20))
    # JSON: parameter eksekusi (misal: {"variant": "spearphishing_link", "target_url": "..."})
    _task_params: Mapped[str | None] = mapped_column("task_params", Text)

    # ─── Status ───────────────────────────────────────────────────────────────
    # pending | assigned | running | completed | failed | timeout | cancelled
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    priority: Mapped[int] = mapped_column(Integer, default=5)   # 1=highest, 10=lowest

    # ─── Hasil ────────────────────────────────────────────────────────────────
    result_output: Mapped[str | None] = mapped_column(Text)
    result_status: Mapped[str | None] = mapped_column(String(20))  # success | failed | partial
    error_message: Mapped[str | None] = mapped_column(Text)
    # JSON: artefak yang dihasilkan agent
    _artifacts: Mapped[str | None] = mapped_column("artifacts", Text)
    # JSON: data yang dikumpulkan agent
    _collected_data: Mapped[str | None] = mapped_column("collected_data", Text)

    # ─── Timeout ──────────────────────────────────────────────────────────────
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=300)   # 5 menit default

    # ─── Timestamps ───────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    assigned_at: Mapped[datetime | None] = mapped_column(DateTime)
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    duration_seconds: Mapped[float | None] = mapped_column(Float)

    # ─── Relationships ────────────────────────────────────────────────────────
    agent: Mapped["Agent"] = relationship("Agent", back_populates="tasks")

    # ─── Properties ───────────────────────────────────────────────────────────
    @property
    def task_params(self) -> dict:
        return json.loads(self._task_params or "{}")

    @task_params.setter
    def task_params(self, value: dict) -> None:
        self._task_params = json.dumps(value)

    @property
    def artifacts(self) -> list[str]:
        return json.loads(self._artifacts or "[]")

    @artifacts.setter
    def artifacts(self, value: list[str]) -> None:
        self._artifacts = json.dumps(value)

    @property
    def collected_data(self) -> dict:
        return json.loads(self._collected_data or "{}")

    @collected_data.setter
    def collected_data(self, value: dict) -> None:
        self._collected_data = json.dumps(value)

    @property
    def is_terminal(self) -> bool:
        return self.status in {"completed", "failed", "timeout", "cancelled"}

    def compute_duration(self) -> float | None:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    def __repr__(self) -> str:
        return (
            f"<AgentTask id={self.id!r} type={self.task_type!r} "
            f"technique={self.technique_id!r} status={self.status!r}>"
        )
