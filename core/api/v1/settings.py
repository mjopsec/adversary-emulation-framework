"""
Settings API — baca dan update konfigurasi Shannon AI dari .env file.

GET  /settings/shannon          : Baca konfigurasi Shannon (API key di-mask)
PATCH /settings/shannon         : Update Shannon config dan reload settings
POST /settings/shannon/test     : Test koneksi ke Shannon API
"""

import re
from pathlib import Path

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.config import BASE_DIR, get_settings

router = APIRouter(prefix="/settings", tags=["settings"])

ENV_FILE = BASE_DIR / ".env"

# Mapping field name → env key
_SHANNON_FIELDS = {
    "api_key": "SHANNON_API_KEY",
    "base_url": "SHANNON_BASE_URL",
    "model": "SHANNON_MODEL",
    "max_tokens": "SHANNON_MAX_TOKENS",
}


def _read_env_value(key: str) -> str | None:
    """Baca nilai dari .env file untuk key tertentu."""
    if not ENV_FILE.exists():
        return None
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith(f"{key}="):
            val = line[len(key) + 1:].strip()
            # Hapus quote jika ada
            if (val.startswith('"') and val.endswith('"')) or \
               (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            return val
    return None


def _write_env_value(key: str, value: str) -> None:
    """Update atau tambah key=value di .env file."""
    if not ENV_FILE.exists():
        ENV_FILE.write_text(f"{key}={value}\n", encoding="utf-8")
        return

    content = ENV_FILE.read_text(encoding="utf-8")
    pattern = re.compile(rf"^{re.escape(key)}=.*$", re.MULTILINE)

    if pattern.search(content):
        new_content = pattern.sub(f"{key}={value}", content)
    else:
        # Tambah di akhir
        new_content = content.rstrip("\n") + f"\n{key}={value}\n"

    ENV_FILE.write_text(new_content, encoding="utf-8")


def _mask_key(key: str | None) -> str:
    """Tampilkan hanya 8 karakter pertama dan terakhir dari API key."""
    if not key:
        return ""
    if len(key) <= 16:
        return "•" * len(key)
    return key[:8] + "•" * (len(key) - 12) + key[-4:]


# ─── Schema ───────────────────────────────────────────────────────────────────

class ShannonConfigRead(BaseModel):
    api_key_masked: str
    api_key_set: bool
    base_url: str
    model: str
    max_tokens: int
    is_configured: bool


class ShannonConfigUpdate(BaseModel):
    api_key: str | None = None       # None = jangan ubah
    base_url: str | None = None
    model: str | None = None
    max_tokens: int | None = None


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/shannon", response_model=ShannonConfigRead, summary="Baca konfigurasi Shannon AI")
async def get_shannon_config() -> ShannonConfigRead:
    s = get_settings()
    return ShannonConfigRead(
        api_key_masked=_mask_key(s.shannon_api_key),
        api_key_set=bool(s.shannon_api_key),
        base_url=s.shannon_base_url,
        model=s.shannon_model,
        max_tokens=s.shannon_max_tokens,
        is_configured=s.has_shannon_configured,
    )


@router.patch("/shannon", response_model=ShannonConfigRead, summary="Update konfigurasi Shannon AI")
async def update_shannon_config(body: ShannonConfigUpdate) -> ShannonConfigRead:
    """
    Update satu atau lebih field Shannon config di .env file.
    Perubahan berlaku langsung — settings di-reload otomatis.
    """
    if body.api_key is not None:
        _write_env_value("SHANNON_API_KEY", body.api_key)
    if body.base_url is not None:
        url = body.base_url.rstrip("/")
        _write_env_value("SHANNON_BASE_URL", url)
    if body.model is not None:
        _write_env_value("SHANNON_MODEL", body.model)
    if body.max_tokens is not None:
        _write_env_value("SHANNON_MAX_TOKENS", str(body.max_tokens))

    # Invalidate lru_cache agar nilai baru terbaca
    get_settings.cache_clear()

    s = get_settings()
    return ShannonConfigRead(
        api_key_masked=_mask_key(s.shannon_api_key),
        api_key_set=bool(s.shannon_api_key),
        base_url=s.shannon_base_url,
        model=s.shannon_model,
        max_tokens=s.shannon_max_tokens,
        is_configured=s.has_shannon_configured,
    )


@router.post("/shannon/test", summary="Test koneksi ke Shannon AI API")
async def test_shannon_connection() -> dict:
    """
    Kirim request minimal ke Shannon API untuk verifikasi koneksi dan API key.
    Tidak mengkonsumsi token secara signifikan.
    """
    s = get_settings()
    if not s.has_shannon_configured:
        raise HTTPException(status_code=400, detail="Shannon API key belum dikonfigurasi.")

    headers = {
        "Authorization": f"Bearer {s.shannon_api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": s.shannon_model,
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 5,
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{s.shannon_base_url}/chat/completions",
                headers=headers,
                json=payload,
            )
    except httpx.ConnectError as e:
        return {"success": False, "error": f"Tidak dapat terhubung ke {s.shannon_base_url}: {e}"}
    except httpx.TimeoutException:
        return {"success": False, "error": f"Timeout — server tidak merespons dalam 15 detik."}
    except Exception as e:
        return {"success": False, "error": str(e)}

    if resp.status_code == 200:
        data = resp.json()
        model_used = data.get("model", s.shannon_model)
        return {
            "success": True,
            "message": f"Koneksi berhasil — model: {model_used}",
            "base_url": s.shannon_base_url,
            "model": model_used,
            "status_code": 200,
        }
    elif resp.status_code == 401:
        return {"success": False, "error": "API key tidak valid (401 Unauthorized)."}
    elif resp.status_code == 402:
        return {"success": False, "error": "Quota habis (402 Payment Required)."}
    elif resp.status_code == 404:
        return {"success": False, "error": f"Endpoint tidak ditemukan — periksa Base URL. ({s.shannon_base_url})"}
    else:
        return {"success": False, "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
