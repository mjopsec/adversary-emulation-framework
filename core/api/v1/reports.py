"""
Reports API Endpoints (Phase 6).

GET  /reports/campaigns/{id}               : JSON campaign report
GET  /reports/campaigns/{id}/html          : HTML campaign report (download)
GET  /reports/campaigns/{id}/pdf           : PDF campaign report (download)
GET  /reports/campaigns/{id}/navigator     : ATT&CK Navigator layer JSON

GET  /reports/purple/{session_id}          : JSON purple team report
GET  /reports/purple/{session_id}/html     : HTML purple report (download)
GET  /reports/purple/{session_id}/pdf      : PDF purple report (download)

GET  /reports/navigator                    : Platform-wide Navigator layer (semua kampanye)
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_session
from core.detection.purple_team import PurpleTeamManager
from core.models.campaign import Campaign
from core.models.purple_session import PurpleSession
from core.reporting.generator import ReportGenerator
from core.reporting.html_generator import generate_campaign_html, generate_purple_html
from core.reporting.pdf_generator import generate_campaign_pdf, generate_purple_pdf

router = APIRouter(prefix="/reports", tags=["reports"])

DBSession = Annotated[AsyncSession, Depends(get_session)]


# ─── Campaign Reports ─────────────────────────────────────────────────────────

@router.get(
    "/campaigns/{campaign_id}",
    summary="JSON campaign report lengkap",
)
async def campaign_report_json(campaign_id: str, db: DBSession) -> dict:
    """
    Laporan kampanye dalam format JSON.
    Mencakup: summary, execution timeline, findings, dan ATT&CK Navigator layer.
    """
    gen = ReportGenerator(db)
    try:
        return await gen.generate_json_report(campaign_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get(
    "/campaigns/{campaign_id}/html",
    summary="HTML campaign report (download)",
    response_class=HTMLResponse,
)
async def campaign_report_html(campaign_id: str, db: DBSession) -> HTMLResponse:
    """
    Laporan kampanye dalam format HTML self-contained.
    Siap dibuka di browser — tidak memerlukan koneksi internet.
    """
    gen = ReportGenerator(db)
    try:
        report_data = await gen.generate_json_report(campaign_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    html = generate_campaign_html(report_data)
    filename = f"report_{campaign_id[:8]}.html"
    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "/campaigns/{campaign_id}/pdf",
    summary="PDF campaign report (download)",
)
async def campaign_report_pdf(campaign_id: str, db: DBSession) -> Response:
    """
    Laporan kampanye dalam format PDF.
    Mencakup: cover page, executive summary, execution timeline, findings, dan Sigma hints.
    """
    gen = ReportGenerator(db)
    try:
        report_data = await gen.generate_json_report(campaign_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    pdf_bytes = generate_campaign_pdf(report_data)
    filename = f"report_{campaign_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "/campaigns/{campaign_id}/navigator",
    summary="ATT&CK Navigator layer untuk kampanye ini",
)
async def campaign_navigator_layer(campaign_id: str, db: DBSession) -> dict:
    """
    Export ATT&CK Navigator layer JSON dari hasil kampanye.
    Import ke https://mitre-attack.github.io/attack-navigator/ untuk visualisasi heatmap.

    Teknik yang tidak terdeteksi ditampilkan putih (gap), terdeteksi sebagian oranye,
    terdeteksi penuh merah.
    """
    gen = ReportGenerator(db)
    try:
        report_data = await gen.generate_json_report(campaign_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return report_data.get("navigator_layer", {})


# ─── Purple Team Reports ──────────────────────────────────────────────────────

@router.get(
    "/purple/{session_id}",
    summary="JSON purple team report lengkap",
)
async def purple_report_json(session_id: str, db: DBSession) -> dict:
    """
    Laporan purple team session dalam format JSON.
    Mencakup: metrik coverage, MTTD, event detail, dan rekomendasi prioritas.
    """
    manager = PurpleTeamManager(db)
    try:
        report = await manager.generate_report(session_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return report.to_dict()


@router.get(
    "/purple/{session_id}/html",
    summary="HTML purple team report (download)",
    response_class=HTMLResponse,
)
async def purple_report_html(session_id: str, db: DBSession) -> HTMLResponse:
    """
    Laporan purple team dalam format HTML self-contained.
    Mencakup: coverage bars per tactic, event table berwarna, Sigma hints, rekomendasi.
    """
    manager = PurpleTeamManager(db)
    try:
        report = await manager.generate_report(session_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    html = generate_purple_html(report.to_dict())
    filename = f"purple_{session_id[:8]}.html"
    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "/purple/{session_id}/pdf",
    summary="PDF purple team report (download)",
)
async def purple_report_pdf(session_id: str, db: DBSession) -> Response:
    """
    Laporan purple team dalam format PDF.
    Mencakup: cover page, coverage summary, event detail, Sigma hints, dan rekomendasi.
    """
    manager = PurpleTeamManager(db)
    try:
        report = await manager.generate_report(session_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    pdf_bytes = generate_purple_pdf(report.to_dict())
    filename = f"purple_{session_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ─── Platform-wide Navigator ──────────────────────────────────────────────────

@router.get(
    "/navigator",
    summary="ATT&CK Navigator layer gabungan semua kampanye",
)
async def platform_navigator_layer(
    db: DBSession,
    environment: str | None = Query(None, description="Filter: it | ot | hybrid_it_ot"),
    limit: int = Query(20, ge=1, le=100, description="Maks kampanye yang digabungkan"),
) -> dict:
    """
    Gabungkan findings dari semua kampanye menjadi satu ATT&CK Navigator layer.
    Berguna untuk melihat postur deteksi keseluruhan platform.

    Score tiap teknik = rata-rata gap score dari semua kampanye yang mengeksekusinya.
    """
    query = select(Campaign).order_by(Campaign.created_at.desc()).limit(limit)
    if environment:
        query = query.where(Campaign.environment_type == environment)

    result = await db.execute(query)
    campaigns = result.scalars().all()

    if not campaigns:
        return {
            "name": "AEP — Platform Overview (No Data)",
            "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
            "domain": "enterprise-attack",
            "techniques": [],
        }

    # Kumpulkan semua laporan dan gabungkan teknik
    gen = ReportGenerator(db)
    technique_scores: dict[str, list[int]] = {}

    for camp in campaigns:
        try:
            rpt = await gen.generate_json_report(camp.id)
            for tech in rpt.get("navigator_layer", {}).get("techniques", []):
                tid = tech["techniqueID"]
                technique_scores.setdefault(tid, []).append(tech["score"])
        except Exception:
            continue

    # Rata-ratakan score
    techniques = [
        {
            "techniqueID": tid,
            "score": round(sum(scores) / len(scores)),
            "enabled": True,
        }
        for tid, scores in technique_scores.items()
    ]

    # Tentukan domain berdasarkan kampanye terbanyak
    ot_count = sum(1 for c in campaigns if c.environment_type == "ot")
    domain = "ics-attack" if ot_count > len(campaigns) / 2 else "enterprise-attack"

    return {
        "name": f"AEP — Platform Overview ({len(campaigns)} campaigns)",
        "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain": domain,
        "description": (
            f"Gabungan {len(campaigns)} kampanye. "
            f"Score = rata-rata gap score (100 = tidak terdeteksi, 0 = terdeteksi penuh)."
        ),
        "techniques": techniques,
        "gradient": {
            "colors": ["#4CAF50", "#ffffff", "#f44336"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Terdeteksi Penuh (0)", "color": "#4CAF50"},
            {"label": "Tidak Terdeteksi / Gap (100)", "color": "#f44336"},
        ],
    }
