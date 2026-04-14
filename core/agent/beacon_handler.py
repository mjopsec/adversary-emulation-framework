"""
Beacon Handler — Endpoint logic untuk agent check-in dan task result submission.

Modul ini memisahkan logika beacon dari routing HTTP agar bisa diuji secara unit
dan digunakan kembali oleh transport layer yang berbeda (HTTP, WebSocket, dll.).

Beacon protocol:
  1. Agent POST /agents/{id}/checkin dengan token + system_info
  2. Server kembalikan daftar tasks pending
  3. Agent eksekusi tasks, POST hasil ke /agents/{id}/tasks/{task_id}/result
  4. Server simpan hasil dan update execution record

Security:
  - Token rahasia 32 byte hex, dibuat saat registrasi
  - Hanya agent dengan token yang benar bisa check-in
  - Rate limiting: max 1 check-in per 5 detik (dihandle di API layer)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from core.agent.agent_manager import AgentManager


@dataclass
class CheckinRequest:
    """Data yang dikirim agent saat check-in."""
    agent_id: str
    token: str
    # Info sistem yang dikumpulkan agent
    system_info: dict[str, Any] = field(default_factory=dict)
    # Status agent saat check-in
    current_tasks_running: int = 0
    memory_mb: int | None = None
    cpu_percent: float | None = None


@dataclass
class CheckinResponse:
    """Response dari server ke agent yang check-in."""
    authenticated: bool
    agent_id: str | None = None
    tasks: list[dict] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    server_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    next_checkin_seconds: int = 60

    def to_dict(self) -> dict:
        return {
            "authenticated": self.authenticated,
            "agent_id": self.agent_id,
            "tasks": self.tasks,
            "pending_tasks": self.tasks,   # alias — agent reads this key
            "commands": self.commands,
            "server_time": self.server_time,
            "next_checkin_seconds": self.next_checkin_seconds,
        }


@dataclass
class TaskResultRequest:
    """Data yang dikirim agent setelah menyelesaikan task."""
    agent_id: str
    token: str
    task_id: str
    result_status: str          # success | failed | partial | timeout
    output: str = ""
    error: str = ""
    artifacts: list[str] = field(default_factory=list)
    collected_data: dict = field(default_factory=dict)
    # Waktu eksekusi di sisi agent
    started_at: str | None = None
    completed_at: str | None = None


class BeaconHandler:
    """
    Handler untuk proses beacon check-in dan task result.

    Dirancang sebagai pure logic layer (tanpa HTTP dependency)
    agar bisa diuji secara unit dan digunakan lintas transport.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.manager = AgentManager(session)

    async def handle_checkin(self, request: CheckinRequest) -> CheckinResponse:
        """
        Proses beacon check-in dari agent.

        Flow:
        1. Verifikasi token agent
        2. Update last_seen dan status
        3. Ambil pending tasks
        4. Kembalikan tasks ke agent
        """
        logger.debug("Beacon check-in dari agent: {}", request.agent_id)

        # Bangun system_info dengan resource usage
        system_info = dict(request.system_info)
        if request.memory_mb is not None:
            system_info["memory_mb"] = request.memory_mb
        if request.cpu_percent is not None:
            system_info["cpu_percent"] = request.cpu_percent
        if request.current_tasks_running > 0:
            system_info["tasks_running"] = request.current_tasks_running

        result = await self.manager.process_checkin(
            agent_id=request.agent_id,
            token=request.token,
            system_info=system_info,
        )

        if not result.get("authenticated"):
            logger.warning("Autentikasi beacon gagal untuk agent: {}", request.agent_id)
            return CheckinResponse(authenticated=False)

        # Tentukan interval check-in berikutnya berdasarkan jumlah tasks
        # Jika ada tasks, check-in lebih cepat
        next_interval = 60
        if result["tasks"]:
            next_interval = 10  # Check-in lebih sering saat ada tasks
        elif len(result["tasks"]) == 0:
            next_interval = 60  # Normal interval

        return CheckinResponse(
            authenticated=True,
            agent_id=request.agent_id,
            tasks=result["tasks"],
            commands=result.get("commands", []),
            next_checkin_seconds=next_interval,
        )

    async def handle_task_result(self, request: TaskResultRequest) -> dict:
        """
        Proses hasil task yang dikirim agent.

        Returns:
            {"success": bool, "message": str}
        """
        logger.debug(
            "Task result dari agent {}: task={} status={}",
            request.agent_id, request.task_id, request.result_status,
        )

        success = await self.manager.submit_task_result(
            agent_id=request.agent_id,
            token=request.token,
            task_id=request.task_id,
            result_status=request.result_status,
            output=request.output,
            error=request.error,
            artifacts=request.artifacts,
            collected_data=request.collected_data,
        )

        if not success:
            return {
                "success": False,
                "message": "Task tidak ditemukan atau autentikasi gagal.",
            }

        return {
            "success": True,
            "message": f"Hasil task {request.task_id} berhasil disimpan.",
            "task_id": request.task_id,
        }

    async def get_agent_status(self, agent_id: str, token: str) -> dict:
        """
        Kembalikan status agent dan statistik tasks.
        Digunakan oleh agent untuk self-diagnostic.
        """
        from sqlalchemy import select
        from core.models.agent import Agent, AgentTask

        result = await self.session.execute(
            select(Agent).where(Agent.id == agent_id, Agent.token == token)
        )
        agent = result.scalar_one_or_none()

        if not agent:
            return {"authenticated": False}

        tasks = await self.manager.get_agent_tasks(agent_id)
        task_summary = {
            "total": len(tasks),
            "pending": sum(1 for t in tasks if t.status == "pending"),
            "running": sum(1 for t in tasks if t.status == "running"),
            "completed": sum(1 for t in tasks if t.status == "completed"),
            "failed": sum(1 for t in tasks if t.status == "failed"),
        }

        return {
            "authenticated": True,
            "agent_id": agent_id,
            "status": agent.status,
            "hostname": agent.hostname,
            "last_seen": agent.last_seen.isoformat() if agent.last_seen else None,
            "check_in_count": agent.check_in_count,
            "tasks": task_summary,
        }
