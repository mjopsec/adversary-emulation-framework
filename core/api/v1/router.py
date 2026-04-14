"""
Router utama API v1 — gabungkan semua sub-router di sini.
"""

from fastapi import APIRouter

from core.api.v1 import agents, apt_profiles, campaigns, health, phase3, purple_team, reports, stix, techniques

api_router = APIRouter()

# ─── System ───────────────────────────────────────────────────────────────────
api_router.include_router(health.router)

# ─── Core Resources ───────────────────────────────────────────────────────────
api_router.include_router(campaigns.router)
api_router.include_router(techniques.router)
api_router.include_router(apt_profiles.router)

# ─── Phase 3: AI Decision Engine Penuh ───────────────────────────────────────
api_router.include_router(phase3.router)

# ─── Phase 4: Agent Framework ─────────────────────────────────────────────────
api_router.include_router(agents.router)

# ─── Phase 5: Detection Validation + Purple Team ──────────────────────────────
api_router.include_router(purple_team.router)

# ─── Phase 6: Reporting Engine ────────────────────────────────────────────────
api_router.include_router(reports.router)

# ─── Phase 7: STIX 2.1 Export ─────────────────────────────────────────────────
api_router.include_router(stix.router)
