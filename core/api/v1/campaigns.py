"""
API endpoints untuk manajemen Campaign.
CRUD + operasi kontrol (start, abort, step execution).
"""

from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Body, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_session
from core.engine.ai_decision import AIDecisionEngine
from core.engine.campaign_runner import CampaignRunner
from core.models.campaign import Campaign, CampaignStep
from core.schemas.campaign import (
    CampaignCreate,
    CampaignRead,
    CampaignStepCreate,
    CampaignStepRead,
    CampaignUpdate,
)
from core.config import get_settings

router = APIRouter(prefix="/campaigns", tags=["campaigns"])

DBSession = Annotated[AsyncSession, Depends(get_session)]


def get_ai_engine() -> AIDecisionEngine:
    return AIDecisionEngine(get_settings())


def get_campaign_runner(
    db: DBSession,
    ai_engine: Annotated[AIDecisionEngine, Depends(get_ai_engine)],
) -> CampaignRunner:
    return CampaignRunner(get_settings(), ai_engine, db)


# ─── CRUD Campaigns ───────────────────────────────────────────────────────────

@router.post(
    "/",
    response_model=CampaignRead,
    status_code=status.HTTP_201_CREATED,
    summary="Buat kampanye baru",
)
async def create_campaign(
    data: CampaignCreate,
    db: DBSession,
) -> CampaignRead:
    """
    Buat kampanye baru dalam status 'draft'.
    Kampanye belum bisa dieksekusi sebelum divalidasi dan diaktifkan.
    """
    campaign = Campaign(
        id=str(uuid4()),
        name=data.name,
        description=data.description,
        client_name=data.client_name,
        engagement_type=data.engagement_type,
        environment_type=data.environment_type,
        rules_of_engagement=data.rules_of_engagement,
        emergency_contact=data.emergency_contact,
        start_date=data.start_date,
        end_date=data.end_date,
        production_safe_mode=data.production_safe_mode,
        apt_profile_id=data.apt_profile_id,
        status="draft",
    )
    campaign.target_ips = data.target_ips
    campaign.target_domains = data.target_domains
    campaign.excluded_targets = data.excluded_targets
    campaign.objectives = data.objectives

    db.add(campaign)
    await db.commit()
    await db.refresh(campaign)
    return CampaignRead.model_validate(campaign)


@router.get("/", response_model=list[CampaignRead], summary="Daftar semua kampanye")
async def list_campaigns(db: DBSession, status_filter: str | None = None) -> list[CampaignRead]:
    """Ambil semua kampanye, opsional filter berdasarkan status."""
    query = select(Campaign).order_by(Campaign.created_at.desc())
    if status_filter:
        query = query.where(Campaign.status == status_filter)
    result = await db.execute(query)
    campaigns = result.scalars().all()
    return [CampaignRead.model_validate(c) for c in campaigns]


@router.get("/{campaign_id}", response_model=CampaignRead, summary="Detail kampanye")
async def get_campaign(campaign_id: str, db: DBSession) -> CampaignRead:
    result = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
    campaign = result.scalar_one_or_none()
    if not campaign:
        raise HTTPException(status_code=404, detail="Kampanye tidak ditemukan.")
    return CampaignRead.model_validate(campaign)


@router.patch("/{campaign_id}", response_model=CampaignRead, summary="Update kampanye")
async def update_campaign(
    campaign_id: str,
    data: CampaignUpdate,
    db: DBSession,
) -> CampaignRead:
    result = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
    campaign = result.scalar_one_or_none()
    if not campaign:
        raise HTTPException(status_code=404, detail="Kampanye tidak ditemukan.")
    if campaign.status == "active":
        raise HTTPException(
            status_code=400,
            detail="Kampanye yang sedang aktif tidak bisa diupdate. Pause dulu.",
        )

    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        if hasattr(campaign, key):
            setattr(campaign, key, value)

    await db.commit()
    await db.refresh(campaign)
    return CampaignRead.model_validate(campaign)


@router.delete("/{campaign_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Hapus kampanye")
async def delete_campaign(campaign_id: str, db: DBSession) -> None:
    result = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
    campaign = result.scalar_one_or_none()
    if not campaign:
        raise HTTPException(status_code=404, detail="Kampanye tidak ditemukan.")
    if campaign.status == "active":
        raise HTTPException(
            status_code=400,
            detail="Tidak bisa menghapus kampanye yang sedang aktif.",
        )
    await db.delete(campaign)
    await db.commit()


# ─── Campaign Control ─────────────────────────────────────────────────────────

@router.post("/{campaign_id}/start", summary="Validasi dan mulai kampanye")
async def start_campaign(
    campaign_id: str,
    runner: Annotated[CampaignRunner, Depends(get_campaign_runner)],
) -> dict:
    """
    Validasi konteks engagement menggunakan AI, lalu aktifkan kampanye.
    Kampanye harus dalam status 'draft' atau 'paused'.
    """
    return await runner.validate_and_start(campaign_id)


@router.post("/{campaign_id}/abort", summary="Hentikan kampanye")
async def abort_campaign(
    campaign_id: str,
    runner: Annotated[CampaignRunner, Depends(get_campaign_runner)],
    reason: str = "",
) -> dict:
    """Hentikan semua aktivitas kampanye dan tandai sebagai aborted."""
    success = await runner.abort_campaign(campaign_id, reason)
    if not success:
        raise HTTPException(status_code=404, detail="Kampanye tidak ditemukan.")
    return {"success": True, "message": "Kampanye berhasil dihentikan."}


# ─── Campaign Steps ───────────────────────────────────────────────────────────

@router.post(
    "/{campaign_id}/steps",
    response_model=CampaignStepRead,
    status_code=status.HTTP_201_CREATED,
    summary="Tambah langkah ke kampanye",
)
async def add_campaign_step(
    campaign_id: str,
    data: CampaignStepCreate,
    db: DBSession,
) -> CampaignStepRead:
    result = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
    campaign = result.scalar_one_or_none()
    if not campaign:
        raise HTTPException(status_code=404, detail="Kampanye tidak ditemukan.")

    step = CampaignStep(
        campaign_id=campaign_id,
        order_index=data.order_index,
        phase=data.phase,
        technique_id=data.technique_id,
        method=data.method,
        success_condition=data.success_condition,
        fallback_action=data.fallback_action,
        notes=data.notes,
        risk_assessment=data.risk_assessment,
    )
    db.add(step)
    await db.commit()
    await db.refresh(step)
    return CampaignStepRead.model_validate(step)


@router.delete(
    "/{campaign_id}/steps/{step_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Hapus langkah kampanye",
)
async def delete_campaign_step(campaign_id: str, step_id: str, db: DBSession) -> None:
    result = await db.execute(
        select(CampaignStep).where(CampaignStep.id == step_id, CampaignStep.campaign_id == campaign_id)
    )
    step = result.scalar_one_or_none()
    if not step:
        raise HTTPException(status_code=404, detail="Step tidak ditemukan.")
    await db.delete(step)
    await db.commit()


@router.get(
    "/{campaign_id}/steps",
    response_model=list[CampaignStepRead],
    summary="Daftar langkah kampanye",
)
async def list_campaign_steps(campaign_id: str, db: DBSession) -> list[CampaignStepRead]:
    result = await db.execute(
        select(CampaignStep)
        .where(CampaignStep.campaign_id == campaign_id)
        .order_by(CampaignStep.order_index)
    )
    steps = result.scalars().all()
    return [CampaignStepRead.model_validate(s) for s in steps]


class RunStepRequest(BaseModel):
    """Body opsional untuk override command yang direncanakan Shannon."""
    override_command: str | None = None
    override_task_type: str | None = None  # shell_command | powershell | python_exec
    reiterate: bool = False               # Aktifkan self-healing loop untuk kali_ssh
    max_iter: int = 4                     # Maks iterasi reiterate (1–8)


@router.get("/{campaign_id}/steps/{step_id}/plan", summary="Rencanakan langkah (tanpa eksekusi)")
async def plan_campaign_step(
    campaign_id: str,
    step_id: str,
    target: str,
    db: DBSession,
    evasion_context: str | None = None,
    campaign_context: str | None = None,
) -> dict:
    """
    Minta Shannon AI merencanakan perintah untuk teknik ini terhadap target.
    Tidak mengeksekusi apapun — hanya mengembalikan rencana yang bisa diubah.
    """
    from sqlalchemy.orm import selectinload
    from core.agent.task_dispatcher import TaskDispatcher

    step_result = await db.execute(
        select(CampaignStep)
        .options(selectinload(CampaignStep.technique))
        .where(CampaignStep.id == step_id)
    )
    step = step_result.scalar_one_or_none()
    if not step:
        raise HTTPException(status_code=404, detail="Step tidak ditemukan.")

    from core.config import Settings as _Settings
    settings = _Settings()  # baca langsung dari .env
    dispatcher = TaskDispatcher(db)
    tech_info = await dispatcher._get_technique_info(step.technique_id)

    # Cek apakah ada agent di target
    agent = await dispatcher.manager.find_agent_for_target(
        target_ip=target,
        campaign_id=campaign_id,
        agent_type="it",
    )

    active_agent = agent if (agent and agent.is_active) else None
    try:
        plan_result = await dispatcher.plan_with_alternatives(
            technique_id=step.technique_id,
            tech_info=tech_info,
            agent=active_agent,
            settings=settings,
            evasion_context=evasion_context,
            campaign_context=campaign_context,
            target=target,
        )
    except Exception as e:
        msg = str(e)
        if "rate-limited" in msg.lower() or "429" in msg or "quota" in msg.lower() or "402" in msg:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=msg or "Shannon API sedang rate-limited. Tunggu beberapa saat lalu coba lagi.",
            )
        raise HTTPException(status_code=500, detail=f"Shannon error: {msg}")

    primary = plan_result["primary"]
    return {
        "has_agent": active_agent is not None,
        "agent_id": active_agent.id if active_agent else None,
        "agent_hostname": active_agent.hostname if active_agent else None,
        "agent_os": active_agent.os_type if active_agent else "unknown",
        "agent_privilege": active_agent.privilege_level if active_agent else None,
        "agent_capabilities": active_agent.capabilities if active_agent else [],
        "technique_id": step.technique_id,
        "technique_name": tech_info.get("name", step.technique_id),
        "tactic": tech_info.get("tactic", ""),
        "target": target,
        "task_type": primary["task_type"],
        "command": primary["command"],
        "explanation": primary.get("explanation", ""),
        "alternatives": plan_result.get("alternatives", []),
        "art_alternatives": plan_result.get("art_alternatives", []),
        "has_art": plan_result.get("has_art", False),
    }


@router.post("/{campaign_id}/steps/{step_id}/generate-script", summary="Generate konten script yang dirujuk dalam payload")
async def generate_script_for_step(
    campaign_id: str,
    step_id: str,
    script_url: str,
    db: DBSession,
    command_context: str = "",
) -> dict:
    """
    Minta Shannon AI membuat konten script yang disebutkan dalam payload.
    Contoh: jika payload mengandung 'http://host/shell.ps1', Shannon akan
    menulis konten shell.ps1 yang fungsional sesuai teknik ATT&CK.
    """
    from core.agent.task_dispatcher import TaskDispatcher
    from core.config import Settings as _Settings

    step_result = await db.execute(select(CampaignStep).where(CampaignStep.id == step_id))
    step = step_result.scalar_one_or_none()
    if not step:
        raise HTTPException(status_code=404, detail="Step tidak ditemukan.")

    settings = _Settings()
    dispatcher = TaskDispatcher(db)
    tech_info = await dispatcher._get_technique_info(step.technique_id)

    return await dispatcher.generate_script(
        technique_id=step.technique_id,
        tech_info=tech_info,
        script_url=script_url,
        command_context=command_context,
        settings=settings,
    )


@router.post("/{campaign_id}/steps/{step_id}/run", summary="Eksekusi langkah kampanye")
async def run_campaign_step(
    campaign_id: str,
    step_id: str,
    target: str,
    runner: Annotated[CampaignRunner, Depends(get_campaign_runner)],
    body: RunStepRequest = Body(default_factory=RunStepRequest),
) -> dict:
    """
    Eksekusi satu langkah kampanye terhadap target.
    Jika body berisi override_command, perintah tersebut dijalankan langsung (skip Shannon planning).
    """
    extra_context: dict = {}
    if body.override_command:
        extra_context["override_command"] = body.override_command
        extra_context["override_task_type"] = body.override_task_type or "shell_command"
    if body.reiterate:
        extra_context["reiterate"] = True
        extra_context["max_iter"] = max(1, min(8, body.max_iter))
    return await runner.run_step(campaign_id, step_id, target, extra_context=extra_context)


@router.get("/{campaign_id}/executions", summary="Riwayat eksekusi kampanye")
async def list_campaign_executions(campaign_id: str, db: DBSession) -> list[dict]:
    """
    Kembalikan semua execution records untuk kampanye — termasuk output Shannon AI/agent.
    Di-index per step_id agar frontend bisa lookup per baris.
    """
    from core.models.execution import Execution
    from core.models.finding import Finding
    from sqlalchemy.orm import selectinload

    exec_result = await db.execute(
        select(Execution)
        .where(Execution.campaign_id == campaign_id)
        .order_by(Execution.started_at)
    )
    executions = exec_result.scalars().all()

    # Ambil findings untuk setiap execution
    finding_result = await db.execute(
        select(Finding).where(Finding.campaign_id == campaign_id)
    )
    findings_by_exec: dict[str, list] = {}
    for f in finding_result.scalars().all():
        findings_by_exec.setdefault(f.execution_id, []).append({
            "severity": f.severity,
            "detected": f.detected,
            "detection_quality": f.detection_quality,
            "gap_description": f.gap_description,
            "sigma_rule": f.sigma_rule,
        })

    def _infer_dispatched_via(result_detail: str | None) -> str | None:
        if not result_detail:
            return None
        first = result_detail.lstrip()
        if first.startswith("[Agent:"):
            return "agent"
        if first.startswith("[Shannon AI Simulation"):
            return "shannon_ai"
        if first.startswith("[SIMULATION"):
            return "simulation"
        return "registry"

    return [
        {
            "id": ex.id,
            "step_id": ex.step_id,
            "technique_id": ex.technique_id,
            "technique_name": ex.technique_name,
            "tactic": ex.tactic if hasattr(ex, "tactic") else None,
            "target": ex.target,
            "status": ex.status,
            "result_detail": ex.result_detail,
            "error_message": ex.error_message,
            "duration_seconds": ex.duration_seconds,
            "started_at": ex.started_at.isoformat() if ex.started_at else None,
            "dispatched_via": _infer_dispatched_via(ex.result_detail),
            "findings": findings_by_exec.get(ex.id, []),
        }
        for ex in executions
    ]


class SuggestNextStepRequest(BaseModel):
    target: str | None = None
    previous_results: list[dict] = []   # [{technique_id, tactic, status, result_detail}]
    existing_techniques: list[str] = []


@router.post(
    "/{campaign_id}/suggest-next-step",
    summary="Shannon merekomendasikan langkah kill chain berikutnya",
)
async def suggest_next_step(
    campaign_id: str,
    body: SuggestNextStepRequest,
    db: DBSession,
) -> dict:
    """
    Berikan konteks eksekusi sebelumnya kepada Shannon, dapatkan rekomendasi
    teknik ATT&CK berikutnya yang paling relevan + command konkret.

    Shannon menganalisis output dari langkah-langkah sebelumnya (service yang
    ditemukan, kredensial yang terkumpul, privilege level) untuk menentukan
    langkah logis berikutnya dalam kill chain post-compromise.
    """
    from core.agent.task_dispatcher import TaskDispatcher
    from core.config import Settings as _Settings

    # Ambil campaign untuk context environment
    result = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
    campaign = result.scalar_one_or_none()
    if not campaign:
        raise HTTPException(status_code=404, detail="Kampanye tidak ditemukan.")

    settings = _Settings()
    dispatcher = TaskDispatcher(db)

    # Cari agent aktif untuk target
    agent = None
    if body.target:
        agent = await dispatcher.manager.find_agent_for_target(
            target_ip=body.target,
            campaign_id=campaign_id,
            agent_type="it",
        )
        if agent and not agent.is_active:
            agent = None

    try:
        suggestion = await dispatcher.suggest_next_step(
            previous_results=body.previous_results,
            existing_techniques=body.existing_techniques,
            agent=agent,
            settings=settings,
            environment=campaign.environment_type or "it",
            target=body.target,
        )
    except Exception as e:
        msg = str(e)
        if "rate-limited" in msg.lower() or "429" in msg or "quota" in msg.lower() or "402" in msg:
            raise HTTPException(status_code=503, detail=msg)
        raise HTTPException(status_code=500, detail=f"Shannon error: {msg}")

    return suggestion
