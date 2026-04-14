"""
API Endpoints untuk Agent Framework (Phase 4).

Endpoints:
  POST /agents/register           : Daftarkan agent baru, dapatkan token
  GET  /agents/                   : Daftar semua agents
  GET  /agents/{id}               : Detail agent
  DELETE /agents/{id}             : Terminasi agent
  POST /agents/{id}/checkin       : Beacon check-in (dipanggil agent)
  POST /agents/{id}/tasks/{tid}/result : Submit hasil task
  GET  /agents/{id}/tasks         : Daftar tasks agent
  POST /agents/{id}/tasks         : Queue task manual ke agent
  POST /agents/mark-stale         : Tandai agents stale (admin)
  POST /campaigns/{id}/dispatch   : Dispatch teknik via agent/simulasi
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from core.agent.agent_manager import AgentManager
from core.agent.beacon_handler import BeaconHandler, CheckinRequest, TaskResultRequest
from core.agent.task_dispatcher import TaskDispatcher
from core.database import get_session

router = APIRouter(tags=["agents"])

DBSession = Annotated[AsyncSession, Depends(get_session)]


# ─── Pydantic Request Schemas ─────────────────────────────────────────────────

class AgentRegisterRequest(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=255)
    ip_address: str | None = None
    os_type: str = "unknown"
    os_version: str | None = None
    arch: str | None = None
    agent_type: str = Field("it", pattern="^(it|ot)$")
    agent_name: str = "aep-agent"
    agent_version: str | None = None
    capabilities: list[str] | None = None
    campaign_id: str | None = None
    beacon_interval: int = Field(60, ge=10, le=3600)
    ot_protocol: str | None = None
    ot_zone: str | None = None
    privilege_level: str = "user"
    metadata_extra: dict[str, Any] | None = None


class AgentCheckinRequest(BaseModel):
    token: str
    system_info: dict[str, Any] = Field(default_factory=dict)
    current_tasks_running: int = 0
    memory_mb: int | None = None
    cpu_percent: float | None = None


class TaskResultSubmitRequest(BaseModel):
    token: str
    result_status: str = Field(..., pattern="^(success|failed|partial|timeout)$")
    output: str = ""
    error: str = ""
    artifacts: list[str] = Field(default_factory=list)
    collected_data: dict[str, Any] = Field(default_factory=dict)


class QueueTaskRequest(BaseModel):
    task_type: str = Field("execute_technique")
    technique_id: str | None = None
    task_params: dict[str, Any] = Field(default_factory=dict)
    campaign_id: str | None = None
    priority: int = Field(5, ge=1, le=10)
    timeout_seconds: int = Field(300, ge=30, le=3600)


class DispatchRequest(BaseModel):
    technique_id: str
    target_ip: str
    production_safe_mode: bool = True
    extra_context: dict[str, Any] = Field(default_factory=dict)
    prefer_agent: bool = True


# ─── Agent Registration & Management ─────────────────────────────────────────

@router.post(
    "/agents/register",
    summary="Daftarkan agent baru",
    status_code=status.HTTP_201_CREATED,
)
async def register_agent(data: AgentRegisterRequest, db: DBSession) -> dict:
    """
    Daftarkan agent baru ke platform.

    Response mencakup **token** yang harus disimpan di sisi agent.
    Token hanya ditampilkan sekali dan tidak bisa di-retrieve ulang.
    """
    manager = AgentManager(db)
    agent = await manager.register(
        hostname=data.hostname,
        ip_address=data.ip_address,
        os_type=data.os_type,
        os_version=data.os_version,
        arch=data.arch,
        agent_type=data.agent_type,
        agent_name=data.agent_name,
        agent_version=data.agent_version,
        capabilities=data.capabilities,
        campaign_id=data.campaign_id,
        beacon_interval=data.beacon_interval,
        ot_protocol=data.ot_protocol,
        ot_zone=data.ot_zone,
        privilege_level=data.privilege_level,
        metadata_extra=data.metadata_extra,
    )
    summary = manager.get_agent_summary(agent)
    summary["token"] = agent.token  # ONLY time token is exposed
    return {
        "success": True,
        "agent": summary,
        "message": (
            "Agent berhasil terdaftar. SIMPAN token ini — tidak bisa ditampilkan ulang. "
            f"Gunakan token ini untuk autentikasi beacon ke /agents/{agent.id}/checkin"
        ),
    }


@router.get("/agents/", summary="Daftar semua agents")
async def list_agents(
    db: DBSession,
    campaign_id: str | None = Query(None),
    status_filter: str | None = Query(None, alias="status"),
    agent_type: str | None = Query(None),
) -> list[dict]:
    manager = AgentManager(db)
    agents = await manager.list_agents(
        campaign_id=campaign_id,
        status=status_filter,
        agent_type=agent_type,
    )
    return [manager.get_agent_summary(a) for a in agents]


@router.get("/agents/{agent_id}", summary="Detail agent")
async def get_agent(agent_id: str, db: DBSession) -> dict:
    from sqlalchemy import select
    from core.models.agent import Agent

    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent tidak ditemukan.")
    manager = AgentManager(db)
    return manager.get_agent_summary(agent)


@router.delete("/agents/{agent_id}", summary="Terminasi agent")
async def terminate_agent(
    agent_id: str,
    db: DBSession,
    reason: str = Query("", description="Alasan terminasi"),
) -> dict:
    manager = AgentManager(db)
    success = await manager.terminate_agent(agent_id, reason)
    if not success:
        raise HTTPException(status_code=404, detail="Agent tidak ditemukan.")
    return {"success": True, "message": f"Agent {agent_id} berhasil di-terminate."}


@router.post("/agents/mark-stale", summary="Tandai agents stale (maintenance)")
async def mark_stale_agents(db: DBSession) -> dict:
    """Periksa semua active agents dan tandai yang tidak check-in sebagai stale."""
    manager = AgentManager(db)
    count = await manager.mark_stale_agents()
    return {"stale_marked": count, "message": f"{count} agents ditandai sebagai stale."}


# ─── Beacon Endpoints ─────────────────────────────────────────────────────────

@router.post(
    "/agents/{agent_id}/checkin",
    summary="Beacon check-in (dipanggil oleh agent)",
)
async def agent_checkin(
    agent_id: str,
    data: AgentCheckinRequest,
    db: DBSession,
) -> dict:
    """
    Endpoint yang dipanggil secara periodik oleh agent untuk:
    1. Menandai diri sebagai active
    2. Mengambil pending tasks
    3. Melaporkan system info
    """
    handler = BeaconHandler(db)
    request = CheckinRequest(
        agent_id=agent_id,
        token=data.token,
        system_info=data.system_info,
        current_tasks_running=data.current_tasks_running,
        memory_mb=data.memory_mb,
        cpu_percent=data.cpu_percent,
    )
    response = await handler.handle_checkin(request)

    if not response.authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token agent tidak valid atau agent sudah di-terminate.",
        )

    return response.to_dict()


@router.get(
    "/agents/{agent_id}/status",
    summary="Status agent (dipanggil oleh agent)",
)
async def agent_status(
    agent_id: str,
    db: DBSession,
    token: str = Query(..., description="Token autentikasi agent"),
) -> dict:
    """Self-diagnostic endpoint untuk agent."""
    handler = BeaconHandler(db)
    result = await handler.get_agent_status(agent_id, token)
    if not result.get("authenticated"):
        raise HTTPException(status_code=401, detail="Token tidak valid.")
    return result


# ─── Task Management ──────────────────────────────────────────────────────────

@router.get("/agents/{agent_id}/tasks", summary="Daftar tasks agent")
async def list_agent_tasks(
    agent_id: str,
    db: DBSession,
    status_filter: str | None = Query(None, alias="status"),
) -> list[dict]:
    manager = AgentManager(db)
    tasks = await manager.get_agent_tasks(agent_id, status=status_filter)
    return [
        {
            "id": t.id,
            "task_type": t.task_type,
            "technique_id": t.technique_id,
            "status": t.status,
            "priority": t.priority,
            "params": t.task_params,
            "result_status": t.result_status,
            "output": t.result_output,
            "artifacts": t.artifacts,
            "collected_data": t.collected_data,
            "created_at": t.created_at.isoformat(),
            "completed_at": t.completed_at.isoformat() if t.completed_at else None,
            "duration_seconds": t.duration_seconds,
        }
        for t in tasks
    ]


@router.post(
    "/agents/{agent_id}/tasks",
    summary="Queue task manual ke agent",
    status_code=status.HTTP_201_CREATED,
)
async def queue_task(
    agent_id: str,
    data: QueueTaskRequest,
    db: DBSession,
) -> dict:
    """Tambahkan task ke antrian agent secara manual (tanpa perlu campaign)."""
    # Cek agent ada
    from sqlalchemy import select
    from core.models.agent import Agent

    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent tidak ditemukan.")
    if agent.status == "terminated":
        raise HTTPException(status_code=400, detail="Tidak bisa menambah task ke agent yang sudah di-terminate.")

    manager = AgentManager(db)
    task = await manager.queue_task(
        agent_id=agent_id,
        task_type=data.task_type,
        technique_id=data.technique_id,
        task_params=data.task_params,
        campaign_id=data.campaign_id,
        priority=data.priority,
        timeout_seconds=data.timeout_seconds,
    )
    return {
        "success": True,
        "task_id": task.id,
        "status": task.status,
        "message": f"Task berhasil di-queue untuk agent {agent.hostname}.",
    }


@router.post(
    "/agents/{agent_id}/tasks/{task_id}/result",
    summary="Submit hasil task (dipanggil oleh agent)",
)
async def submit_task_result(
    agent_id: str,
    task_id: str,
    data: TaskResultSubmitRequest,
    db: DBSession,
) -> dict:
    """Agent mengirimkan hasil eksekusi task."""
    handler = BeaconHandler(db)
    request = TaskResultRequest(
        agent_id=agent_id,
        token=data.token,
        task_id=task_id,
        result_status=data.result_status,
        output=data.output,
        error=data.error,
        artifacts=data.artifacts,
        collected_data=data.collected_data,
    )
    result = await handler.handle_task_result(request)
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return result


@router.post(
    "/agents/{agent_id}/tasks/{task_id}/cancel",
    summary="Batalkan task yang pending",
)
async def cancel_task(agent_id: str, task_id: str, db: DBSession) -> dict:
    manager = AgentManager(db)
    success = await manager.cancel_task(task_id)
    if not success:
        raise HTTPException(
            status_code=400,
            detail="Task tidak ditemukan atau sudah selesai/dibatalkan.",
        )
    return {"success": True, "task_id": task_id}


# ─── Campaign Dispatch ────────────────────────────────────────────────────────

@router.post(
    "/campaigns/{campaign_id}/dispatch",
    summary="Dispatch teknik via agent atau simulasi",
)
async def dispatch_technique(
    campaign_id: str,
    data: DispatchRequest,
    db: DBSession,
) -> dict:
    """
    Dispatch eksekusi teknik terhadap target.

    Dispatcher secara otomatis:
    1. Mencari agent aktif untuk target IP (jika prefer_agent=true)
    2. Jika agent ditemukan → route via agent (realistic execution)
    3. Jika tidak ada agent → fallback ke registry/simulasi lokal
    """
    dispatcher = TaskDispatcher(db)
    result = await dispatcher.dispatch(
        technique_id=data.technique_id,
        target_ip=data.target_ip,
        campaign_id=campaign_id,
        production_safe_mode=data.production_safe_mode,
        extra_context=data.extra_context,
        prefer_agent=data.prefer_agent,
    )
    return result.to_dict()
