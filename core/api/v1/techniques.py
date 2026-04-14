"""API endpoints untuk katalog Technique (read-only) dan Registry info."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Annotated

from core.database import get_session
from core.models.technique import Technique
from core.schemas.technique import TechniqueRead
from core.config import get_settings

router = APIRouter(prefix="/techniques", tags=["techniques"])

DBSession = Annotated[AsyncSession, Depends(get_session)]


@router.get("/", response_model=list[TechniqueRead], summary="Daftar teknik ATT&CK")
async def list_techniques(
    db: DBSession,
    environment: str | None = Query(None, description="Filter: it | ot | both"),
    tactic: str | None = Query(None, description="Filter berdasarkan taktik"),
    search: str | None = Query(None, description="Cari berdasarkan nama atau ID"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[TechniqueRead]:
    """
    Ambil katalog teknik ATT&CK dengan filter opsional.
    Data ini di-load dari MITRE ATT&CK Enterprise dan ICS.
    """
    query = select(Technique)

    if environment:
        query = query.where(
            or_(Technique.environment == environment, Technique.environment == "both")
        )
    if tactic:
        query = query.where(Technique.tactic == tactic)
    if search:
        query = query.where(
            or_(
                Technique.id.ilike(f"%{search}%"),
                Technique.name.ilike(f"%{search}%"),
            )
        )

    query = query.order_by(Technique.id).limit(limit).offset(offset)
    result = await db.execute(query)
    return [TechniqueRead.model_validate(t) for t in result.scalars().all()]


@router.get("/{technique_id}", response_model=TechniqueRead, summary="Detail teknik")
async def get_technique(technique_id: str, db: DBSession) -> TechniqueRead:
    result = await db.execute(
        select(Technique).where(Technique.id == technique_id.upper())
    )
    technique = result.scalar_one_or_none()
    if not technique:
        raise HTTPException(status_code=404, detail=f"Teknik {technique_id} tidak ditemukan.")
    return TechniqueRead.model_validate(technique)


@router.get("/tactic/{tactic_name}", response_model=list[TechniqueRead])
async def techniques_by_tactic(tactic_name: str, db: DBSession) -> list[TechniqueRead]:
    """Ambil semua teknik untuk taktik ATT&CK tertentu."""
    result = await db.execute(
        select(Technique).where(Technique.tactic == tactic_name).order_by(Technique.id)
    )
    return [TechniqueRead.model_validate(t) for t in result.scalars().all()]


@router.get("/{technique_id}/impl", summary="Implementasi konkret teknik di Registry")
async def get_technique_impl(technique_id: str) -> dict:
    """
    Kembalikan metadata implementasi teknik dari TechniqueRegistry.
    Termasuk PAYLOAD_TEMPLATES, INTERPRETERS, VARIANTS (jika ada).
    404 jika teknik tidak memiliki implementasi konkret.
    """
    from core.techniques.registry import TechniqueRegistry
    registry = TechniqueRegistry.instance()
    cls = registry.get_class(technique_id.upper())
    if cls is None:
        raise HTTPException(
            status_code=404,
            detail=f"Teknik {technique_id} tidak memiliki implementasi konkret di registry.",
        )

    result: dict = {
        "technique_id": cls.technique_id,
        "name": getattr(cls, "name", ""),
        "tactic": getattr(cls, "tactic", ""),
        "risk_level": getattr(cls, "risk_level", ""),
        "is_destructive": getattr(cls, "is_destructive", False),
        "requires_elevated": getattr(cls, "requires_elevated_privileges", False),
        "environments": [e.value for e in (getattr(cls, "supported_environments", []) or [])],
        "payload_templates": {},
        "interpreters": {},
        "variants": [],
    }

    # PAYLOAD_TEMPLATES — dict str→str
    pt = getattr(cls, "PAYLOAD_TEMPLATES", None)
    if pt and isinstance(pt, dict):
        result["payload_templates"] = {k: str(v) for k, v in pt.items()}

    # INTERPRETERS — dict str→dict
    interp = getattr(cls, "INTERPRETERS", None)
    if interp and isinstance(interp, dict):
        result["interpreters"] = {
            k: {
                "detection_risk": v.get("detection_risk"),
                "edr_alert_prone": v.get("edr_alert_prone"),
                "description": v.get("description", ""),
            }
            for k, v in interp.items()
        }

    # VARIANTS — list of dicts or list of strings
    variants = getattr(cls, "VARIANTS", None)
    if variants:
        if isinstance(variants, list):
            result["variants"] = [
                {"name": v.get("name", str(v)), "description": v.get("description", "")}
                if isinstance(v, dict) else {"name": str(v), "description": ""}
                for v in variants
            ]
        elif isinstance(variants, dict):
            result["variants"] = [
                {"name": k, "description": v.get("description", str(v)) if isinstance(v, dict) else str(v)}
                for k, v in variants.items()
            ]

    return result


@router.post("/{technique_id}/examples", summary="Generate AI payload examples via Shannon")
async def generate_technique_examples(
    technique_id: str,
    db: DBSession,
) -> dict:
    """
    Generate contoh payload dan command untuk teknik ATT&CK menggunakan Shannon AI.
    Requires SHANNON_API_KEY dikonfigurasi di .env.

    Shannon adalah red team AI yang menghasilkan contoh konkret per platform
    (Windows LOLBins, Linux shell, tools seperti Cobalt Strike, Metasploit, dll).
    """
    from core.engine.shannon_client import get_shannon_client
    from core.config import get_settings

    settings = get_settings()

    if not settings.has_shannon_configured:
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=503,
            content={
                "detail": "Shannon AI tidak dikonfigurasi.",
                "hint": "Tambahkan SHANNON_API_KEY=sk-... ke file .env lalu restart server.",
            },
        )

    # Ambil data teknik dari DB untuk konteks
    result = await db.execute(
        select(Technique).where(Technique.id == technique_id.upper())
    )
    technique = result.scalar_one_or_none()
    if not technique:
        raise HTTPException(status_code=404, detail=f"Teknik {technique_id} tidak ditemukan.")

    t = TechniqueRead.model_validate(technique)

    try:
        shannon = get_shannon_client(settings)
        examples = await shannon.generate_technique_examples(
            technique_id=t.id,
            technique_name=t.name,
            description=t.description or "",
            tactic=t.tactic,
            platforms=t.platforms,
            detection_note=t.detection_note,
        )
        return {"technique_id": t.id, "generated_by": "shannon-ai", **examples}

    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        from loguru import logger
        logger.error("Shannon AI error untuk {}: {}", technique_id, e)
        raise HTTPException(status_code=502, detail=f"Shannon AI error: {e}")


@router.get("/registry/info", summary="Info Technique Registry")
async def registry_info() -> dict:
    """
    Informasi tentang teknik yang memiliki implementasi konkret di registry.
    Teknik dengan implementasi lebih akurat dalam simulasi.
    """
    from core.techniques.registry import TechniqueRegistry
    registry = TechniqueRegistry.instance()
    return registry.info()


@router.post("/suggest-chain", summary="Sarankan rantai serangan")
async def suggest_attack_chain(
    db: DBSession,
    environment: str = Query("it", description="Target environment: it | ot"),
    objectives: list[str] = Query(
        default=["initial_access", "lateral_movement", "data_exfiltration"],
        description="Tujuan kampanye"
    ),
    max_risk: str = Query("high", description="Risiko maksimum: low|medium|high|critical"),
) -> list[dict]:
    """
    Sarankan rantai serangan optimal (ordered steps) berdasarkan tujuan dan environment.
    Setiap langkah mencantumkan teknik terbaik dengan alternatifnya.
    """
    from core.engine.technique_selector import TechniqueSelector
    selector = TechniqueSelector(db)
    return await selector.suggest_attack_chain(
        environment=environment,
        objectives=objectives,
        max_risk=max_risk,
    )
