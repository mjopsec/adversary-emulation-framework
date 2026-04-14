"""
Phase 3 API Endpoints — AI Decision Engine Penuh.

Endpoints:
- POST /builder/generate          : Auto-generate kampanye dari objectives + APT profile
- POST /parser/import             : Import kampanye dari YAML/JSON Campaign-as-Code
- POST /parser/validate           : Validasi Campaign-as-Code tanpa menyimpan
- GET  /campaigns/{id}/attack-path: Visualisasi jalur serangan kampanye
- POST /campaigns/{id}/pivot      : Analisis dan eksekusi pivot engine
- GET  /campaigns/{id}/pivot-summary: Ringkasan riwayat pivot kampanye
"""

from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import get_settings
from core.database import get_session
from core.engine.ai_decision import AIDecisionEngine
from core.engine.campaign_builder import BuilderConfig, CampaignBuilder
from core.engine.pivot_engine import PivotEngine
from core.intel.campaign_parser import CampaignParser, load_campaign_dict
from core.models.campaign import Campaign, CampaignStep
from core.models.execution import Execution
from core.graph.attack_path import build_attack_path

router = APIRouter(tags=["phase3"])

DBSession = Annotated[AsyncSession, Depends(get_session)]

# Singleton pivot engine (per request dalam prod, kebutuhan pivot history)
_pivot_engines: dict[str, PivotEngine] = {}


def get_ai_engine() -> AIDecisionEngine:
    return AIDecisionEngine(get_settings())


def get_pivot_engine(
    db: DBSession,
    ai_engine: Annotated[AIDecisionEngine, Depends(get_ai_engine)],
) -> PivotEngine:
    return PivotEngine(session=db, ai_engine=ai_engine)


# ─── Campaign Builder ─────────────────────────────────────────────────────────

@router.post(
    "/builder/generate",
    summary="Auto-generate kampanye dari objectives + APT profile",
    status_code=status.HTTP_200_OK,
)
async def auto_generate_campaign(
    db: DBSession,
    ai_engine: Annotated[AIDecisionEngine, Depends(get_ai_engine)],
    campaign_name: str = Query(..., description="Nama kampanye yang akan dibuat"),
    environment: str = Query("it", description="Lingkungan target: it | ot | hybrid_it_ot"),
    objectives: list[str] = Query(
        default=["initial_access", "lateral_movement", "data_exfiltration"],
        description="Tujuan kampanye (lihat TechniqueSelector untuk opsi lengkap)",
    ),
    apt_profile_id: str | None = Query(None, description="ID APT profile dari database"),
    max_risk: str = Query("high", description="Level risiko maksimum: low|medium|high|critical"),
    max_steps: int = Query(10, ge=3, le=20, description="Maksimum langkah yang di-generate"),
    description: str | None = Query(None, description="Deskripsi kampanye (opsional)"),
) -> dict:
    """
    Auto-generate kampanye lengkap berdasarkan objectives dan APT profile.

    Builder akan:
    1. Load APT profile dari database (jika ada)
    2. Pilih taktik berdasarkan objectives
    3. Untuk setiap taktik, pilih teknik optimal menggunakan scoring algorithm
    4. Generate AI reasoning untuk setiap langkah
    5. Susun steps dalam urutan kill chain yang logis

    Hasilnya adalah kampanye siap-eksekusi lengkap dengan metadata scoring dan reasoning.
    """
    builder = CampaignBuilder(session=db, settings=get_settings(), ai_engine=ai_engine)

    config = BuilderConfig(
        environment=environment,
        objectives=objectives,
        apt_profile_id=apt_profile_id,
        max_risk=max_risk,
        max_steps=max_steps,
    )

    try:
        generated = await builder.build(
            campaign_name=campaign_name,
            config=config,
            campaign_description=description,
        )
        return generated.to_dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Builder error: {e}")


@router.post(
    "/builder/generate-and-save",
    summary="Auto-generate kampanye dan simpan ke database",
    status_code=status.HTTP_201_CREATED,
)
async def auto_generate_and_save(
    db: DBSession,
    ai_engine: Annotated[AIDecisionEngine, Depends(get_ai_engine)],
    campaign_name: str = Query(...),
    client_name: str = Query(..., description="Nama klien"),
    rules_of_engagement: str = Query(..., description="Rules of Engagement (wajib)"),
    emergency_contact: str = Query(..., description="Kontak darurat"),
    target_ips: list[str] = Query(..., description="Daftar IP/CIDR target"),
    environment: str = Query("it"),
    objectives: list[str] = Query(default=["initial_access", "lateral_movement"]),
    apt_profile_id: str | None = Query(None),
    max_risk: str = Query("high"),
    max_steps: int = Query(10, ge=3, le=20),
) -> dict:
    """
    Auto-generate kampanye dan langsung simpan ke database sebagai draft.
    Returns campaign_id yang bisa digunakan untuk menambah steps dan memulai eksekusi.
    """
    from uuid import uuid4
    from core.models.campaign import Campaign, CampaignStep

    builder = CampaignBuilder(session=db, settings=get_settings(), ai_engine=ai_engine)
    config = BuilderConfig(
        environment=environment,
        objectives=objectives,
        apt_profile_id=apt_profile_id,
        max_risk=max_risk,
        max_steps=max_steps,
    )

    try:
        generated = await builder.build(campaign_name=campaign_name, config=config)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Builder error: {e}")

    # Simpan Campaign ke database
    campaign = Campaign(
        id=str(uuid4()),
        name=campaign_name,
        description=generated.description,
        client_name=client_name,
        engagement_type="greybox",
        environment_type=environment,
        rules_of_engagement=rules_of_engagement,
        emergency_contact=emergency_contact,
        production_safe_mode=True,
        apt_profile_id=apt_profile_id,
        status="draft",
    )
    campaign.target_ips = target_ips
    campaign.target_domains = []
    campaign.excluded_targets = []
    campaign.objectives = objectives

    db.add(campaign)
    await db.flush()  # Dapatkan campaign.id tanpa commit

    # Simpan Steps ke database
    saved_steps = []
    for step_data in generated.to_campaign_steps_create():
        step = CampaignStep(
            campaign_id=campaign.id,
            order_index=step_data["order_index"],
            phase=step_data["phase"],
            technique_id=step_data["technique_id"],
            risk_assessment=step_data.get("risk_assessment", "medium"),
            ai_reasoning=step_data.get("ai_reasoning"),
            estimated_success_rate=step_data.get("estimated_success_rate"),
            fallback_action=step_data.get("fallback_action"),
            notes=step_data.get("notes"),
            method=step_data.get("method"),
        )
        db.add(step)
        saved_steps.append(step_data["technique_id"])

    await db.commit()

    return {
        "success": True,
        "campaign_id": campaign.id,
        "campaign_name": campaign_name,
        "total_steps": len(saved_steps),
        "steps_saved": saved_steps,
        "ai_overview": generated.ai_overview,
        "risk_summary": generated.risk_summary,
        "estimated_duration_hours": generated.estimated_duration_hours,
        "message": (
            f"Kampanye '{campaign_name}' berhasil dibuat dengan {len(saved_steps)} langkah. "
            f"Gunakan POST /campaigns/{campaign.id}/start untuk memulai."
        ),
    }


# ─── Campaign Parser ──────────────────────────────────────────────────────────

@router.post(
    "/parser/validate",
    summary="Validasi Campaign-as-Code YAML/JSON",
)
async def validate_campaign_definition(
    content: dict = Body(..., description="Campaign definition sebagai JSON/dict"),
) -> dict:
    """
    Validasi Campaign-as-Code definition tanpa menyimpan ke database.
    Berguna untuk CI/CD pipeline yang ingin memvalidasi campaign files.
    """
    try:
        parser = CampaignParser()
        parsed = parser.parse_dict(content)
        return {
            "valid": True,
            "warnings": parsed.parse_warnings,
            "summary": {
                "name": parsed.name,
                "client": parsed.client_name,
                "environment": parsed.environment_type,
                "steps": len(parsed.steps),
                "objectives": parsed.objectives,
                "apt_profile": parsed.apt_profile_name,
                "scope_ips": len(parsed.scope.ips),
                "scope_domains": len(parsed.scope.domains),
            },
        }
    except ValueError as e:
        return {
            "valid": False,
            "error": str(e),
            "warnings": [],
        }


@router.post(
    "/parser/import",
    summary="Import Campaign-as-Code dan simpan ke database",
    status_code=status.HTTP_201_CREATED,
)
async def import_campaign_definition(
    db: DBSession,
    content: dict = Body(..., description="Campaign definition sebagai JSON/dict"),
) -> dict:
    """
    Import Campaign-as-Code dan simpan ke database.
    Teknik yang tidak ada di database akan dicatat sebagai warning.
    """
    from uuid import uuid4

    try:
        parser = CampaignParser()
        parsed = parser.parse_dict(content)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=f"Parse error: {e}")

    # Cek apakah RoE ada (wajib untuk create)
    if not parsed.rules_of_engagement:
        raise HTTPException(
            status_code=422,
            detail="rules_of_engagement wajib diisi sebelum import.",
        )

    if not parsed.scope.ips and not parsed.scope.domains:
        raise HTTPException(
            status_code=422,
            detail="Scope tidak boleh kosong. Isi ips atau domains.",
        )

    # Cari APT profile jika disebutkan
    apt_profile_id = None
    if parsed.apt_profile_name:
        from core.models.apt_profile import APTProfile
        apt_result = await db.execute(
            select(APTProfile).where(
                APTProfile.name.ilike(f"%{parsed.apt_profile_name}%")
            )
        )
        apt = apt_result.scalar_one_or_none()
        if apt:
            apt_profile_id = apt.id

    # Simpan Campaign
    campaign = Campaign(
        id=str(uuid4()),
        name=parsed.name,
        description=parsed.description,
        client_name=parsed.client_name,
        engagement_type=parsed.engagement_type,
        environment_type=parsed.environment_type,
        rules_of_engagement=parsed.rules_of_engagement,
        emergency_contact=parsed.emergency_contact,
        start_date=parsed.start_date,
        end_date=parsed.end_date,
        production_safe_mode=parsed.production_safe,
        apt_profile_id=apt_profile_id,
        status="draft",
    )
    campaign.target_ips = parsed.scope.ips
    campaign.target_domains = parsed.scope.domains
    campaign.excluded_targets = parsed.scope.exclude
    campaign.objectives = parsed.objectives

    db.add(campaign)
    await db.flush()

    # Simpan Steps
    skipped_steps: list[str] = []
    saved_steps_count = 0

    for step_data in parsed.to_steps_create_list():
        technique_id = step_data["technique_id"]

        # Verifikasi teknik ada di database
        from core.models.technique import Technique
        tech_result = await db.execute(
            select(Technique).where(Technique.id == technique_id)
        )
        if not tech_result.scalar_one_or_none():
            skipped_steps.append(technique_id)
            continue

        step = CampaignStep(
            campaign_id=campaign.id,
            order_index=step_data["order_index"],
            phase=step_data["phase"],
            technique_id=technique_id,
            method=step_data.get("method"),
            success_condition=step_data.get("success_condition"),
            fallback_action=step_data.get("fallback_action"),
            notes=step_data.get("notes"),
            risk_assessment=step_data.get("risk_assessment", "medium"),
        )
        db.add(step)
        saved_steps_count += 1

    await db.commit()

    return {
        "success": True,
        "campaign_id": campaign.id,
        "campaign_name": parsed.name,
        "steps_saved": saved_steps_count,
        "steps_skipped": skipped_steps,
        "parse_warnings": parsed.parse_warnings,
        "apt_profile_matched": apt_profile_id is not None,
        "message": (
            f"Kampanye '{parsed.name}' berhasil diimport dengan {saved_steps_count} langkah."
            + (f" {len(skipped_steps)} langkah dilewati (teknik tidak ada di DB)." if skipped_steps else "")
        ),
    }


# ─── Attack Path Graph ────────────────────────────────────────────────────────

@router.get(
    "/campaigns/{campaign_id}/attack-path",
    summary="Jalur serangan kampanye (Attack Path Graph)",
)
async def get_attack_path(
    campaign_id: str,
    db: DBSession,
    format: str = Query("dict", description="Format output: dict | navigator | dot"),
) -> Any:
    """
    Bangun dan kembalikan attack path graph dari eksekusi kampanye.

    Format yang tersedia:
    - **dict**: JSON graph dengan nodes, edges, dan statistik
    - **navigator**: ATT&CK Navigator layer JSON (bisa langsung di-import ke navigator)
    - **dot**: Graphviz DOT format untuk visualisasi lokal
    """
    # Cek kampanye ada
    campaign_result = await db.execute(
        select(Campaign).where(Campaign.id == campaign_id)
    )
    campaign = campaign_result.scalar_one_or_none()
    if not campaign:
        raise HTTPException(status_code=404, detail="Kampanye tidak ditemukan.")

    # Ambil semua eksekusi
    exec_result = await db.execute(
        select(Execution)
        .where(Execution.campaign_id == campaign_id)
        .order_by(Execution.started_at)
    )
    executions = exec_result.scalars().all()

    if not executions:
        return {
            "campaign_id": campaign_id,
            "message": "Belum ada eksekusi untuk kampanye ini.",
            "nodes": [],
            "edges": [],
            "statistics": {},
        }

    # Build execution dicts
    exec_dicts = []
    for i, ex in enumerate(executions):
        exec_dicts.append({
            "technique_id": ex.technique_id,
            "technique_name": ex.technique_name or ex.technique_id,
            "tactic": "unknown",  # Akan diisi dari step jika ada
            "status": ex.status,
            "detected": False,    # Akan diisi dari finding jika ada
            "risk_level": "medium",
            "order_index": i,
            "duration_seconds": ex.duration_seconds,
            "target": ex.target,
            "artifacts_created": ex.artifacts_created or [],
            "is_pivot": False,
        })

    # Enrich dengan data finding (deteksi)
    from core.models.finding import Finding
    finding_result = await db.execute(
        select(Finding).where(Finding.campaign_id == campaign_id)
    )
    findings_by_exec: dict[str, bool] = {}
    for f in finding_result.scalars().all():
        findings_by_exec[f.execution_id] = f.detected

    for i, ex in enumerate(executions):
        exec_dicts[i]["detected"] = findings_by_exec.get(ex.id, False)

    # Build graph
    graph = build_attack_path(
        campaign_id=campaign_id,
        campaign_name=campaign.name,
        executions=exec_dicts,
    )

    if format == "navigator":
        return graph.to_navigator_layer()
    elif format == "dot":
        return {"dot": graph.to_graphviz_dot()}
    else:
        return graph.to_dict()


# ─── Pivot Engine ─────────────────────────────────────────────────────────────

@router.post(
    "/campaigns/{campaign_id}/pivot",
    summary="Analisis dan rekomendasikan pivot teknik",
)
async def analyze_pivot(
    campaign_id: str,
    db: DBSession,
    pivot_engine: Annotated[PivotEngine, Depends(get_pivot_engine)],
    failed_technique_id: str = Query(..., description="Teknik yang gagal"),
    current_tactic: str = Query(..., description="Taktik ATT&CK saat ini"),
    environment: str = Query("it", description="Lingkungan: it | ot"),
    execution_status: str = Query("failed", description="Status eksekusi: failed | aborted | partial"),
    result_detail: str = Query("", description="Detail hasil eksekusi untuk analisis"),
    detected: bool = Query(False, description="Apakah terdeteksi oleh blue team"),
    previously_tried: list[str] = Query(default=[], description="Teknik yang sudah dicoba"),
) -> dict:
    """
    Analisis kegagalan dan rekomendasikan teknik pivot terbaik.

    Pivot Engine akan:
    1. Klasifikasi penyebab kegagalan (detected, no_privilege, network_blocked, dll.)
    2. Cari teknik alternatif dari taktik yang sama (lateral pivot)
    3. Jika tidak ada, coba taktik adjacent dalam kill chain (forward pivot)
    4. Berikan reasoning dan context adjustments untuk teknik pengganti
    """
    # Cek kampanye ada
    campaign_result = await db.execute(
        select(Campaign).where(Campaign.id == campaign_id)
    )
    campaign = campaign_result.scalar_one_or_none()
    if not campaign:
        raise HTTPException(status_code=404, detail="Kampanye tidak ditemukan.")

    execution_result = {
        "status": execution_status,
        "result_detail": result_detail,
        "detected": detected,
    }

    decision = await pivot_engine.decide_pivot(
        campaign_id=campaign_id,
        failed_technique_id=failed_technique_id,
        current_tactic=current_tactic,
        environment=environment,
        execution_result=execution_result,
        previously_tried=previously_tried,
    )

    return decision.to_dict()


@router.get(
    "/campaigns/{campaign_id}/pivot-summary",
    summary="Ringkasan riwayat pivot kampanye",
)
async def get_pivot_summary(
    campaign_id: str,
    db: DBSession,
    pivot_engine: Annotated[PivotEngine, Depends(get_pivot_engine)],
) -> dict:
    """
    Dapatkan ringkasan semua keputusan pivot dalam kampanye ini.
    Berguna untuk menganalisis pola pertahanan blue team.
    """
    campaign_result = await db.execute(
        select(Campaign).where(Campaign.id == campaign_id)
    )
    if not campaign_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Kampanye tidak ditemukan.")

    return await pivot_engine.analyze_campaign_pivots(campaign_id)
