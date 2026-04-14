"""Health check dan status endpoint."""

from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel

from core.config import get_settings

router = APIRouter(tags=["system"])


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str
    ai_configured: bool
    database: str


@router.get("/health", response_model=HealthResponse, summary="Health check")
async def health_check() -> HealthResponse:
    """
    Cek status aplikasi.
    Digunakan oleh monitoring, load balancer, dan desktop GUI untuk memastikan backend aktif.
    """
    settings = get_settings()
    return HealthResponse(
        status="ok",
        version=settings.app_version,
        timestamp=datetime.now(timezone.utc).isoformat(),
        ai_configured=settings.has_ai_configured,
        database=settings.database_url.split("///")[0],  # Hanya tipe DB, bukan path
    )


@router.get("/info", summary="Informasi platform")
async def platform_info() -> dict:
    """Informasi lengkap tentang konfigurasi platform (tanpa secrets)."""
    settings = get_settings()
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "debug": settings.debug,
        "ai_model": settings.ai_model if settings.has_ai_configured else "tidak dikonfigurasi",
        "ai_available": settings.has_ai_configured,
        "production_safe_mode_default": settings.default_production_safe,
        "attack_data": {
            "enterprise": settings.enterprise_attack_path.exists(),
            "ics": settings.ics_attack_path.exists(),
        },
    }
