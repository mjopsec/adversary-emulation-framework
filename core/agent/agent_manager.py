"""
Agent Manager — Lifecycle management untuk semua agent yang terdaftar.

Tanggung jawab:
1. Registrasi agent baru (generate token, simpan ke DB)
2. Update status agent berdasarkan heartbeat
3. Deteksi agent stale (tidak check-in terlalu lama)
4. Pencarian agent yang cocok untuk target tertentu
5. Terminasi agent

Konsep beacon:
- Agent check-in secara periodik (default 60 detik)
- Saat check-in, agent mengirim info system dan mengambil pending tasks
- Manager memperbarui last_seen dan mengubah status → active
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from loguru import logger
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from core.models.agent import Agent, AgentTask


class AgentManager:
    """
    Manajer lifecycle untuk semua agent.

    Digunakan oleh:
    - API endpoint /agents untuk CRUD
    - Beacon handler saat agent check-in
    - Task dispatcher saat mencari agent untuk target
    """

    # Interval stale detection: jika tidak check-in > 3x beacon_interval
    STALE_MULTIPLIER = 3

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # ─── Registrasi ───────────────────────────────────────────────────────────

    async def register(
        self,
        hostname: str,
        ip_address: str | None = None,
        os_type: str = "unknown",
        os_version: str | None = None,
        arch: str | None = None,
        agent_type: str = "it",
        agent_name: str = "aep-agent",
        agent_version: str | None = None,
        capabilities: list[str] | None = None,
        campaign_id: str | None = None,
        beacon_interval: int = 60,
        ot_protocol: str | None = None,
        ot_zone: str | None = None,
        privilege_level: str = "user",
        metadata_extra: dict | None = None,
    ) -> Agent:
        """
        Daftarkan agent baru. Kembalikan Agent dengan token yang ter-generate.
        Token hanya ditampilkan sekali — simpan di sisi agent.
        """
        agent = Agent(
            hostname=hostname,
            ip_address=ip_address,
            os_type=os_type,
            os_version=os_version,
            arch=arch,
            agent_type=agent_type,
            agent_name=agent_name,
            agent_version=agent_version,
            campaign_id=campaign_id,
            beacon_interval_seconds=beacon_interval,
            ot_protocol=ot_protocol,
            ot_zone=ot_zone,
            privilege_level=privilege_level,
            status="registered",
            notes=None,
        )
        agent.capabilities = capabilities or self._default_capabilities(agent_type)
        if metadata_extra:
            agent.metadata_extra = metadata_extra

        self.session.add(agent)
        await self.session.commit()
        await self.session.refresh(agent)

        logger.info(
            "Agent terdaftar: {} ({}) host={} type={}",
            agent.id, agent.agent_name, hostname, agent_type,
        )
        return agent

    # ─── Beacon / Check-in ────────────────────────────────────────────────────

    async def process_checkin(
        self,
        agent_id: str,
        token: str,
        system_info: dict | None = None,
    ) -> dict:
        """
        Proses check-in dari agent. Verifikasi token, update status, kembalikan tasks.

        Returns:
            {
                "authenticated": bool,
                "tasks": list[dict],  # Tasks yang harus dieksekusi
                "commands": list[str],  # Perintah tambahan
            }
        """
        agent = await self._get_agent(agent_id)
        if not agent:
            logger.warning("Check-in dari agent tidak dikenal: {}", agent_id)
            return {"authenticated": False, "tasks": [], "commands": []}

        if agent.token != token:
            logger.warning("Token tidak valid untuk agent {}", agent_id)
            return {"authenticated": False, "tasks": [], "commands": []}

        if agent.status == "terminated":
            logger.warning("Check-in dari agent yang sudah di-terminate: {}", agent_id)
            return {"authenticated": False, "tasks": [], "commands": ["self_destruct"]}

        # Update agent info
        agent.last_seen = datetime.now(timezone.utc).replace(tzinfo=None)
        agent.check_in_count += 1
        agent.status = "active"

        if system_info:
            extra = agent.metadata_extra
            extra.update(system_info)
            agent.metadata_extra = extra
            # Update privilege level jika dilaporkan
            if "privilege_level" in system_info:
                agent.privilege_level = system_info["privilege_level"]
            if "has_elevated" in system_info:
                agent.has_elevated = bool(system_info["has_elevated"])

        await self.session.commit()

        # Ambil pending tasks untuk agent ini
        pending_tasks = await self._get_pending_tasks(agent_id)

        # Mark tasks sebagai assigned
        task_dicts = []
        for task in pending_tasks:
            task.status = "assigned"
            task.assigned_at = datetime.now(timezone.utc).replace(tzinfo=None)
            task_dicts.append({
                "id": task.id,           # agent reads "id"
                "task_id": task.id,      # alias for compatibility
                "task_type": task.task_type,
                "technique_id": task.technique_id,
                "task_params": task.task_params,  # agent reads "task_params"
                "params": task.task_params,        # alias for other consumers
                "timeout_seconds": task.timeout_seconds,
                "priority": task.priority,
            })

        await self.session.commit()

        logger.debug(
            "Agent {} check-in #{} | {} pending tasks",
            agent.hostname, agent.check_in_count, len(task_dicts),
        )
        return {
            "authenticated": True,
            "agent_id": agent_id,
            "tasks": sorted(task_dicts, key=lambda t: t["priority"]),
            "commands": [],
        }

    async def submit_task_result(
        self,
        agent_id: str,
        token: str,
        task_id: str,
        result_status: str,
        output: str = "",
        error: str = "",
        artifacts: list[str] | None = None,
        collected_data: dict | None = None,
    ) -> bool:
        """
        Agent mengirimkan hasil eksekusi task.
        Returns True jika berhasil disimpan.
        """
        agent = await self._get_agent(agent_id)
        if not agent or agent.token != token:
            return False

        task_result = await self.session.execute(
            select(AgentTask).where(AgentTask.id == task_id, AgentTask.agent_id == agent_id)
        )
        task = task_result.scalar_one_or_none()
        if not task:
            logger.warning("Task {} tidak ditemukan untuk agent {}", task_id, agent_id)
            return False

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        task.status = "completed" if result_status in ("success", "partial") else "failed"
        task.result_status = result_status
        task.result_output = output[:10000] if output else None  # Batas 10k chars
        task.error_message = error[:2000] if error else None
        task.completed_at = now
        task.duration_seconds = task.compute_duration()

        if artifacts:
            task.artifacts = artifacts
        if collected_data:
            task.collected_data = collected_data

        await self.session.commit()

        logger.info(
            "Task {} selesai: agent={} status={} duration={:.1f}s",
            task_id, agent.hostname, result_status,
            task.duration_seconds or 0,
        )
        return True

    # ─── Task Management ──────────────────────────────────────────────────────

    async def queue_task(
        self,
        agent_id: str,
        task_type: str,
        technique_id: str | None = None,
        task_params: dict | None = None,
        campaign_id: str | None = None,
        execution_id: str | None = None,
        priority: int = 5,
        timeout_seconds: int = 300,
    ) -> AgentTask:
        """Tambahkan task ke antrian agent."""
        task = AgentTask(
            agent_id=agent_id,
            campaign_id=campaign_id,
            execution_id=execution_id,
            task_type=task_type,
            technique_id=technique_id,
            priority=priority,
            timeout_seconds=timeout_seconds,
            status="pending",
        )
        task.task_params = task_params or {}
        self.session.add(task)
        await self.session.commit()
        await self.session.refresh(task)
        logger.debug(
            "Task di-queue: type={} technique={} agent={}",
            task_type, technique_id, agent_id,
        )
        return task

    async def cancel_task(self, task_id: str) -> bool:
        """Batalkan task yang belum dimulai."""
        result = await self.session.execute(
            select(AgentTask).where(AgentTask.id == task_id)
        )
        task = result.scalar_one_or_none()
        if not task or task.is_terminal:
            return False
        task.status = "cancelled"
        await self.session.commit()
        return True

    # ─── Lookup ───────────────────────────────────────────────────────────────

    async def find_agent_for_target(
        self,
        target_ip: str,
        campaign_id: str | None = None,
        agent_type: str = "it",
    ) -> Agent | None:
        """
        Cari agent aktif yang paling cocok untuk target IP.

        Prioritas:
        1. Agent di kampanye yang sama + IP match
        2. Agent di kampanye yang sama (IP apapun)
        3. Agent manapun yang aktif + IP match (tanpa filter campaign)
        4. Agent manapun yang aktif (fallback terakhir)
        """
        base_query = select(Agent).where(
            Agent.status == "active",
            Agent.agent_type == agent_type,
        ).order_by(Agent.last_seen.desc())

        # Pass 1: cari di kampanye ini saja
        if campaign_id:
            result = await self.session.execute(
                base_query.where(Agent.campaign_id == campaign_id)
            )
            campaign_agents = result.scalars().all()

            # Prioritas: exact IP match di kampanye ini
            for agent in campaign_agents:
                if agent.ip_address == target_ip:
                    logger.debug("Agent ditemukan (campaign+IP match): {} @ {}", agent.hostname, agent.ip_address)
                    return agent

            # Fallback: agent manapun di kampanye (IP tidak match tapi campaign match)
            if campaign_agents:
                logger.debug("Agent ditemukan (campaign match, no IP match): {}", campaign_agents[0].hostname)
                return campaign_agents[0]

        # Pass 2: cari di semua agent aktif, tanpa filter campaign
        result = await self.session.execute(base_query)
        all_agents = result.scalars().all()

        # Exact IP match (agent mungkin terdaftar tanpa campaign_id)
        for agent in all_agents:
            if agent.ip_address == target_ip:
                logger.debug("Agent ditemukan (global IP match): {} @ {}", agent.hostname, agent.ip_address)
                return agent

        # Fallback terakhir: agent aktif apapun
        if all_agents:
            logger.debug("Agent ditemukan (global fallback): {}", all_agents[0].hostname)
            return all_agents[0]

        return None

    async def list_agents(
        self,
        campaign_id: str | None = None,
        status: str | None = None,
        agent_type: str | None = None,
    ) -> list[Agent]:
        """Daftar agents dengan filter opsional."""
        query = select(Agent).order_by(Agent.registered_at.desc())
        if campaign_id:
            query = query.where(Agent.campaign_id == campaign_id)
        if status:
            query = query.where(Agent.status == status)
        if agent_type:
            query = query.where(Agent.agent_type == agent_type)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_agent_tasks(
        self, agent_id: str, status: str | None = None
    ) -> list[AgentTask]:
        """Ambil daftar tasks untuk agent tertentu."""
        query = select(AgentTask).where(AgentTask.agent_id == agent_id)
        if status:
            query = query.where(AgentTask.status == status)
        query = query.order_by(AgentTask.priority, AgentTask.created_at)
        result = await self.session.execute(query)
        return list(result.scalars().all())

    # ─── Status Management ────────────────────────────────────────────────────

    async def terminate_agent(self, agent_id: str, reason: str = "") -> bool:
        """Terminasi agent — agent tidak akan menerima task baru."""
        agent = await self._get_agent(agent_id)
        if not agent:
            return False
        agent.status = "terminated"
        agent.terminated_at = datetime.now(timezone.utc).replace(tzinfo=None)
        if reason:
            agent.notes = f"Terminated: {reason}"

        # Batalkan semua pending tasks
        await self.session.execute(
            update(AgentTask)
            .where(AgentTask.agent_id == agent_id, AgentTask.status.in_(["pending", "assigned"]))
            .values(status="cancelled")
        )
        await self.session.commit()
        logger.info("Agent {} di-terminate. Alasan: {}", agent_id, reason or "tidak disebutkan")
        return True

    async def mark_stale_agents(self) -> int:
        """
        Tandai agents yang tidak check-in terlalu lama sebagai stale.
        Dipanggil oleh background task periodik.
        Returns: jumlah agents yang di-mark stale.
        """
        from datetime import timedelta
        result = await self.session.execute(
            select(Agent).where(Agent.status == "active")
        )
        agents = result.scalars().all()

        stale_count = 0
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        for agent in agents:
            if agent.last_seen is None:
                continue
            threshold = agent.beacon_interval_seconds * self.STALE_MULTIPLIER
            if (now - agent.last_seen).total_seconds() > threshold:
                agent.status = "stale"
                stale_count += 1
                logger.warning("Agent {} ({}) di-mark stale.", agent.id, agent.hostname)

        if stale_count:
            await self.session.commit()

        return stale_count

    def get_agent_summary(self, agent: Agent) -> dict:
        """Ringkasan agent untuk API response."""
        return {
            "id": agent.id,
            "hostname": agent.hostname,
            "ip_address": agent.ip_address,
            "os_type": agent.os_type,
            "os_version": agent.os_version,
            "agent_type": agent.agent_type,
            "agent_name": agent.agent_name,
            "status": agent.status,
            "privilege_level": agent.privilege_level,
            "has_elevated": agent.has_elevated,
            "capabilities": agent.capabilities,
            "campaign_id": agent.campaign_id,
            "ot_protocol": agent.ot_protocol,
            "last_seen": agent.last_seen.isoformat() if agent.last_seen else None,
            "check_in_count": agent.check_in_count,
            "beacon_interval_seconds": agent.beacon_interval_seconds,
            "registered_at": agent.registered_at.isoformat(),
        }

    # ─── Private Helpers ──────────────────────────────────────────────────────

    async def _get_agent(self, agent_id: str) -> Agent | None:
        result = await self.session.execute(
            select(Agent).where(Agent.id == agent_id)
        )
        return result.scalar_one_or_none()

    async def _get_pending_tasks(self, agent_id: str) -> list[AgentTask]:
        result = await self.session.execute(
            select(AgentTask)
            .where(AgentTask.agent_id == agent_id, AgentTask.status == "pending")
            .order_by(AgentTask.priority, AgentTask.created_at)
            .limit(10)  # Maksimum 10 tasks per check-in
        )
        return list(result.scalars().all())

    @staticmethod
    def _default_capabilities(agent_type: str) -> list[str]:
        """Kapabilitas default berdasarkan tipe agent."""
        if agent_type == "ot":
            return [
                "modbus_read", "modbus_write",
                "dnp3_read", "dnp3_write",
                "opc_ua_browse", "opc_ua_read",
                "network_scan", "protocol_enum",
            ]
        # IT agent default
        return [
            "execute_cmd", "execute_powershell",
            "file_read", "file_write", "file_delete",
            "network_scan", "port_scan",
            "process_list", "process_inject",
            "registry_read", "registry_write",
            "screenshot", "keylog",
        ]
