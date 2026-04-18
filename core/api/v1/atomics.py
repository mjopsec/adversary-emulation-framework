"""
Atomic Red Team Library API.

GET /atomics                   : Cari / list tests dari library ART lokal
GET /atomics/{technique_id}    : Semua tests untuk satu teknik
GET /atomics/check/{technique} : Apakah ART punya test untuk teknik ini
"""

from fastapi import APIRouter, Query

from core.intel.art_loader import has_atomic_tests, load_atomic_tests

router = APIRouter(prefix="/atomics", tags=["atomic-red-team"])


@router.get("", summary="Cari Atomic Red Team tests dari library lokal")
async def search_atomics(
    technique_id: str | None = Query(None, description="Filter by technique ID (e.g. T1003.001)"),
    platform: str | None = Query(None, description="Filter platform: windows | linux | macos"),
    q: str | None = Query(None, description="Cari berdasarkan nama test"),
) -> list[dict]:
    """
    Kembalikan ART atomic tests dari folder atomics/ lokal.
    Cocok untuk browsing sebelum tambahkan ke campaign.
    """
    from pathlib import Path

    atomics_dir = Path(__file__).parent.parent.parent.parent / "atomics"
    if not atomics_dir.exists():
        return []

    if technique_id:
        technique_ids = [technique_id.upper()]
    else:
        # Ambil semua folder yang namanya seperti T1234 atau T1234.001
        technique_ids = [
            d.name for d in sorted(atomics_dir.iterdir())
            if d.is_dir() and d.name.startswith("T")
        ]

    results = []
    for tid in technique_ids:
        tests = load_atomic_tests(tid, platform_filter=platform)
        for t in tests:
            if q and q.lower() not in t["name"].lower() and q.lower() not in t["description"].lower():
                continue
            results.append({"technique_id": tid, **t})

    return results


@router.get("/{technique_id}", summary="ART tests untuk satu teknik ATT&CK")
async def get_technique_atomics(
    technique_id: str,
    platform: str | None = Query(None),
) -> dict:
    """Kembalikan semua ART atomic tests untuk technique_id tertentu."""
    tid = technique_id.upper()
    tests = load_atomic_tests(tid, platform_filter=platform)
    return {
        "technique_id": tid,
        "has_tests": len(tests) > 0,
        "count": len(tests),
        "tests": tests,
    }


@router.get("/check/{technique_id}", summary="Cek apakah ART punya test untuk teknik ini")
async def check_art_coverage(technique_id: str) -> dict:
    """Quick check — berguna untuk badge coverage di UI."""
    tid = technique_id.upper()
    exists = has_atomic_tests(tid)
    count = len(load_atomic_tests(tid)) if exists else 0
    return {"technique_id": tid, "has_art": exists, "count": count}
