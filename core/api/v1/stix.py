"""
STIX 2.1 Export API Endpoints (Phase 7).

GET  /stix/campaigns/{id}             : STIX Bundle JSON untuk kampanye
GET  /stix/campaigns/{id}/download    : Download .json bundle (Content-Disposition)
GET  /stix/purple/{session_id}        : STIX Bundle JSON untuk purple session gaps
GET  /stix/purple/{session_id}/download : Download .json bundle
GET  /stix/techniques/{technique_id}  : Single ATT&CK technique sebagai AttackPattern
GET  /stix/identity                   : AEP Identity object (untuk TAXII consumers)
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_session
from core.detection.purple_team import PurpleTeamManager
from core.reporting.generator import ReportGenerator
from core.stix import (
    AEP_IDENTITY,
    build_campaign_bundle,
    build_purple_bundle,
    build_technique_bundle,
    bundle_to_dict,
)

router = APIRouter(prefix="/stix", tags=["stix-export"])

DBSession = Annotated[AsyncSession, Depends(get_session)]

_STIX_CONTENT_TYPE = "application/stix+json;version=2.1"


# ─── Campaign Endpoints ───────────────────────────────────────────────────────

@router.get(
    "/campaigns/{campaign_id}",
    summary="STIX 2.1 Bundle untuk kampanye",
)
async def campaign_stix_bundle(campaign_id: str, db: DBSession) -> dict:
    """
    Export kampanye sebagai STIX 2.1 Bundle.

    Bundle berisi:
    - **Identity**: AEP sebagai creator
    - **Campaign**: Metadata kampanye
    - **AttackPattern**: Setiap teknik ATT&CK yang dieksekusi
    - **Indicator**: Detection gaps (teknik yang tidak terdeteksi) dengan Sigma hints
    - **CourseOfAction**: Rekomendasi remediation per teknik
    - **Relationship**: Campaign→uses→AttackPattern, Indicator→indicates→AttackPattern, dll.

    Output kompatibel dengan MISP, OpenCTI, dan TAXII 2.1.
    """
    report_data = await _get_campaign_report(campaign_id, db)
    bundle = build_campaign_bundle(report_data)
    return bundle_to_dict(bundle)


@router.get(
    "/campaigns/{campaign_id}/download",
    summary="Download STIX Bundle kampanye sebagai file .json",
)
async def campaign_stix_download(campaign_id: str, db: DBSession) -> Response:
    """
    Download STIX 2.1 Bundle kampanye sebagai file JSON.
    File ini dapat langsung diimport ke MISP, OpenCTI, atau TAXII server.
    """
    report_data = await _get_campaign_report(campaign_id, db)
    bundle = build_campaign_bundle(report_data)

    import json
    content = bundle.serialize(pretty=True)
    filename = f"stix_campaign_{campaign_id[:8]}.json"
    return Response(
        content=content,
        media_type=_STIX_CONTENT_TYPE,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ─── Purple Team Endpoints ────────────────────────────────────────────────────

@router.get(
    "/purple/{session_id}",
    summary="STIX 2.1 Bundle untuk purple team session",
)
async def purple_stix_bundle(session_id: str, db: DBSession) -> dict:
    """
    Export purple team session sebagai STIX 2.1 Bundle.

    Fokus pada detection gaps:
    - **AttackPattern** per teknik yang di-test
    - **Indicator** per gap (missed detection) dengan Sigma hints sebagai description
    - **CourseOfAction** dari rekomendasi blue team
    - **Relationship** yang menghubungkan semua objek

    Ideal untuk berbagi temuan ke threat intel platform tim blue.
    """
    report_dict = await _get_purple_report(session_id, db)
    bundle = build_purple_bundle(report_dict)
    return bundle_to_dict(bundle)


@router.get(
    "/purple/{session_id}/download",
    summary="Download STIX Bundle purple session sebagai file .json",
)
async def purple_stix_download(session_id: str, db: DBSession) -> Response:
    """Download STIX 2.1 Bundle purple team session sebagai file JSON."""
    report_dict = await _get_purple_report(session_id, db)
    bundle = build_purple_bundle(report_dict)

    content = bundle.serialize(pretty=True)
    filename = f"stix_purple_{session_id[:8]}.json"
    return Response(
        content=content,
        media_type=_STIX_CONTENT_TYPE,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ─── Technique Endpoint ───────────────────────────────────────────────────────

@router.get(
    "/techniques/{technique_id}",
    summary="Single ATT&CK technique sebagai STIX AttackPattern",
)
async def technique_stix(
    technique_id: str,
    name: str | None = Query(None, description="Nama teknik (opsional)"),
    tactic: str | None = Query(None, description="Taktik ATT&CK (contoh: initial_access)"),
) -> dict:
    """
    Export satu teknik ATT&CK sebagai STIX AttackPattern dalam bundle mini.

    Berguna untuk:
    - Lookup teknik individual
    - Inject ke MISP event
    - Test koneksi TAXII
    """
    technique_id = technique_id.upper()
    bundle = build_technique_bundle(
        technique_id=technique_id,
        technique_name=name,
        tactic=tactic,
    )
    return bundle_to_dict(bundle)


# ─── Identity Endpoint ────────────────────────────────────────────────────────

@router.get(
    "/identity",
    summary="AEP Identity object (STIX 2.1)",
)
async def aep_identity() -> dict:
    """
    Kembalikan STIX Identity object untuk AEP.
    Digunakan oleh TAXII consumers untuk memverifikasi created_by_ref.
    """
    import json
    return json.loads(AEP_IDENTITY.serialize())


# ─── Helpers ──────────────────────────────────────────────────────────────────

async def _get_campaign_report(campaign_id: str, db: AsyncSession) -> dict:
    gen = ReportGenerator(db)
    try:
        return await gen.generate_json_report(campaign_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


async def _get_purple_report(session_id: str, db: AsyncSession) -> dict:
    manager = PurpleTeamManager(db)
    try:
        report = await manager.generate_report(session_id)
        return report.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
