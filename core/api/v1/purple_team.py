"""
Purple Team API Endpoints (Phase 5).

POST /purple/sessions                        : Buat sesi baru
GET  /purple/sessions                        : Daftar semua sesi
GET  /purple/sessions/{id}                   : Detail sesi
POST /purple/sessions/{id}/start             : Aktivasi sesi
POST /purple/sessions/{id}/complete          : Selesaikan sesi
POST /purple/sessions/{id}/events            : Catat aksi red team
POST /purple/sessions/{id}/events/{eid}/respond : Blue team merespons
GET  /purple/sessions/{id}/events            : Daftar events sesi
GET  /purple/sessions/{id}/gaps              : Ringkasan gap
GET  /purple/sessions/{id}/report            : Laporan lengkap
GET  /purple/sessions/{id}/sigma/{technique} : Generate Sigma hint untuk teknik
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_session
from core.detection.purple_team import PurpleTeamManager, VALID_BLUE_RESPONSES
from core.detection.validator import DetectionValidator
from core.models.purple_session import PurpleSession, PurpleEvent

router = APIRouter(prefix="/purple", tags=["purple-team"])

DBSession = Annotated[AsyncSession, Depends(get_session)]


# ─── Request Schemas ──────────────────────────────────────────────────────────

class CreateSessionRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    environment: str = Field("it", pattern="^(it|ot|hybrid_it_ot)$")
    campaign_id: str | None = None
    description: str | None = None
    red_team_lead: str | None = None
    blue_team_lead: str | None = None
    facilitator: str | None = None


class UpdateSessionRequest(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None
    red_team_lead: str | None = None
    blue_team_lead: str | None = None
    facilitator: str | None = None


class RecordRedActionRequest(BaseModel):
    technique_id: str = Field(..., description="ATT&CK technique ID (misal: T1566)")
    technique_name: str | None = None
    tactic: str | None = None
    execution_method: str | None = None
    target: str | None = None
    notes: str | None = None


class RecordBlueResponseRequest(BaseModel):
    blue_response: str = Field(
        ...,
        description=f"Respons blue team: {', '.join(sorted(VALID_BLUE_RESPONSES))}",
    )
    detection_latency_seconds: float | None = Field(
        None, description="Berapa detik sampai terdeteksi"
    )
    detected_by: str | None = Field(None, description="Tool yang mendeteksi (SIEM, EDR, Firewall)")
    triggered_alert: str | None = Field(None, description="Nama alert/rule yang trigger")
    notes: str | None = None


# ─── Session Endpoints ────────────────────────────────────────────────────────

@router.post(
    "/sessions",
    summary="Buat purple team session baru",
    status_code=status.HTTP_201_CREATED,
)
async def create_session(data: CreateSessionRequest, db: DBSession) -> dict:
    """
    Buat sesi Purple Team baru dalam status 'draft'.
    Sesi harus di-start sebelum bisa menerima events.
    """
    manager = PurpleTeamManager(db)
    ps = await manager.create_session(
        name=data.name,
        environment=data.environment,
        campaign_id=data.campaign_id,
        description=data.description,
        red_team_lead=data.red_team_lead,
        blue_team_lead=data.blue_team_lead,
        facilitator=data.facilitator,
    )
    return {"success": True, "session": ps.to_summary()}


@router.get("/sessions", summary="Daftar semua purple team sessions")
async def list_sessions(
    db: DBSession,
    status_filter: str | None = Query(None, alias="status"),
    campaign_id: str | None = Query(None),
) -> list[dict]:
    query = select(PurpleSession).order_by(PurpleSession.created_at.desc())
    if status_filter:
        query = query.where(PurpleSession.status == status_filter)
    if campaign_id:
        query = query.where(PurpleSession.campaign_id == campaign_id)
    result = await db.execute(query)
    return [ps.to_summary() for ps in result.scalars().all()]


@router.get("/sessions/{session_id}", summary="Detail purple team session")
async def get_session_detail(session_id: str, db: DBSession) -> dict:
    result = await db.execute(select(PurpleSession).where(PurpleSession.id == session_id))
    ps = result.scalar_one_or_none()
    if not ps:
        raise HTTPException(status_code=404, detail="Session tidak ditemukan.")
    return ps.to_summary()


@router.patch("/sessions/{session_id}", summary="Update purple session metadata")
async def update_session(session_id: str, body: UpdateSessionRequest, db: DBSession) -> dict:
    result = await db.execute(select(PurpleSession).where(PurpleSession.id == session_id))
    ps = result.scalar_one_or_none()
    if not ps:
        raise HTTPException(status_code=404, detail="Session tidak ditemukan.")
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(ps, field, value)
    await db.commit()
    await db.refresh(ps)
    return ps.__dict__


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Hapus purple session")
async def delete_session(session_id: str, db: DBSession) -> None:
    result = await db.execute(select(PurpleSession).where(PurpleSession.id == session_id))
    ps = result.scalar_one_or_none()
    if not ps:
        raise HTTPException(status_code=404, detail="Session tidak ditemukan.")
    if ps.status == "active":
        raise HTTPException(
            status_code=400,
            detail="Session yang sedang aktif tidak bisa dihapus. Complete atau batalkan dulu.",
        )
    await db.delete(ps)
    await db.commit()


@router.post("/sessions/{session_id}/start", summary="Mulai purple session")
async def start_session(session_id: str, db: DBSession) -> dict:
    manager = PurpleTeamManager(db)
    ps = await manager.start_session(session_id)
    if not ps:
        raise HTTPException(
            status_code=400,
            detail="Session tidak ditemukan atau tidak dalam status 'draft'.",
        )
    return {"success": True, "session": ps.to_summary()}


@router.post("/sessions/{session_id}/complete", summary="Selesaikan purple session")
async def complete_session(session_id: str, db: DBSession) -> dict:
    manager = PurpleTeamManager(db)
    ps = await manager.complete_session(session_id)
    if not ps:
        raise HTTPException(
            status_code=400,
            detail="Session tidak ditemukan atau tidak dalam status aktif.",
        )
    return {"success": True, "session": ps.to_summary()}


# ─── Event Endpoints ──────────────────────────────────────────────────────────

@router.post(
    "/sessions/{session_id}/events",
    summary="Catat aksi red team",
    status_code=status.HTTP_201_CREATED,
)
async def record_red_action(
    session_id: str,
    data: RecordRedActionRequest,
    db: DBSession,
) -> dict:
    """
    Catat aksi red team — teknik yang akan/sedang dieksekusi.
    Blue team kemudian memberikan respons via endpoint /respond.
    """
    manager = PurpleTeamManager(db)
    try:
        event = await manager.record_red_team_action(
            session_id=session_id,
            technique_id=data.technique_id,
            technique_name=data.technique_name,
            tactic=data.tactic,
            execution_method=data.execution_method,
            target=data.target,
            notes=data.notes,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {
        "success": True,
        "event_id": event.id,
        "technique_id": event.technique_id,
        "message": (
            f"Aksi red team untuk {event.technique_id} dicatat. "
            f"Gunakan event_id '{event.id}' saat blue team merespons."
        ),
    }


@router.post(
    "/sessions/{session_id}/events/{event_id}/respond",
    summary="Blue team merespons terhadap aksi red team",
)
async def record_blue_response(
    session_id: str,
    event_id: str,
    data: RecordBlueResponseRequest,
    db: DBSession,
) -> dict:
    """
    Blue team mencatat apakah mereka mendeteksi teknik red team.

    Respons yang valid:
    - **detected**: SIEM/SOC/EDR berhasil mendeteksi
    - **blocked**: EDR/firewall memblokir sebelum eksekusi
    - **partial**: Sebagian terdeteksi (alert muncul tapi terlambat/tidak lengkap)
    - **missed**: TIDAK terdeteksi — ini adalah detection GAP
    - **false_positive**: Terdeteksi tapi sebagai false positive (noisy rule)

    Jika `missed`, sistem akan otomatis generate Sigma rule hint dan rekomendasi.
    """
    manager = PurpleTeamManager(db)
    try:
        event = await manager.record_blue_response(
            event_id=event_id,
            blue_response=data.blue_response,
            detection_latency_seconds=data.detection_latency_seconds,
            detected_by=data.detected_by,
            triggered_alert=data.triggered_alert,
            notes=data.notes,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    response = {
        "success": True,
        "event": event.to_dict(),
        "is_gap": event.is_gap,
    }
    if event.is_gap:
        response["gap_alert"] = (
            f"⚠ GAP TERIDENTIFIKASI: {event.technique_id} tidak terdeteksi! "
            f"Severity: {event.gap_severity}. Sigma hint telah di-generate."
        )

    return response


@router.get("/sessions/{session_id}/events", summary="Daftar events dalam session")
async def list_session_events(
    session_id: str,
    db: DBSession,
    gaps_only: bool = Query(False, description="Tampilkan hanya events yang merupakan gap"),
) -> list[dict]:
    query = (
        select(PurpleEvent)
        .where(PurpleEvent.session_id == session_id)
        .order_by(PurpleEvent.created_at)
    )
    if gaps_only:
        query = query.where(PurpleEvent.is_gap == True)  # noqa: E712

    result = await db.execute(query)
    return [e.to_dict() for e in result.scalars().all()]


# ─── Analysis Endpoints ───────────────────────────────────────────────────────

@router.get("/sessions/{session_id}/gaps", summary="Ringkasan gap detection")
async def get_gap_summary(session_id: str, db: DBSession) -> dict:
    """Ringkasan cepat detection gaps tanpa full report."""
    manager = PurpleTeamManager(db)
    return await manager.get_gap_summary(session_id)


@router.get("/sessions/{session_id}/report", summary="Laporan lengkap purple session")
async def get_session_report(session_id: str, db: DBSession) -> dict:
    """
    Generate laporan lengkap purple team session.
    Mencakup: metrik coverage, top gaps, rekomendasi prioritas, dan Sigma hints.
    """
    manager = PurpleTeamManager(db)
    try:
        report = await manager.generate_report(session_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return report.to_dict()


@router.get(
    "/sigma/{technique_id}",
    summary="Generate Sigma rule hint untuk teknik ATT&CK",
)
async def get_sigma_hint(
    technique_id: str,
    execution_method: str | None = Query(None, description="Metode eksekusi spesifik"),
) -> dict:
    """
    Generate Sigma rule hint YAML untuk teknik ATT&CK tertentu.

    Output adalah **hint template** untuk tim blue team — bukan Sigma rule production-ready.
    Sesuaikan dengan log source, threshold, dan environment Anda sebelum deploy.
    """
    validator = DetectionValidator()
    sigma_yaml = validator.generate_sigma_hint(
        technique_id,
        context={"execution_method": execution_method or ""},
    )
    return {
        "technique_id": technique_id.upper(),
        "sigma_yaml": sigma_yaml,
        "note": (
            "Ini adalah hint template — bukan Sigma rule production-ready. "
            "Sesuaikan log source, kondisi, dan threshold dengan environment Anda."
        ),
    }
