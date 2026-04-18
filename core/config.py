"""
Konfigurasi terpusat menggunakan Pydantic Settings.
Semua nilai dapat di-override via environment variables atau file .env.
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ─── Application ──────────────────────────────────────────────────────────
    app_name: str = "AE Platform"
    app_version: str = "1.0.0"
    debug: bool = False

    # ─── API Server ───────────────────────────────────────────────────────────
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1024, le=65535)
    api_prefix: str = "/api/v1"
    secret_key: str = "change-me-in-production-please"

    # ─── Database ─────────────────────────────────────────────────────────────
    database_url: str = f"sqlite+aiosqlite:///{BASE_DIR}/aep.db"

    # ─── AI Engine (Anthropic Claude) ─────────────────────────────────────────
    anthropic_api_key: str | None = None
    ai_model: str = "claude-sonnet-4-6"
    ai_max_tokens: int = Field(default=4096, ge=256, le=16000)

    # ─── Shannon AI (Red Team AI — OpenAI-compatible) ─────────────────────────
    shannon_api_key: str | None = None
    shannon_base_url: str = "https://api.shannon-ai.com/v1"
    shannon_model: str = "shannon-1.6-pro"
    shannon_max_tokens: int = Field(default=2048, ge=256, le=8000)

    # ─── Pentest Box (Kali Linux / Parrot / attacker machine via SSH) ─────────
    pentest_box_host: str | None = None
    pentest_box_port: int = Field(default=22, ge=1, le=65535)
    pentest_box_user: str = "kali"
    pentest_box_password: str = ""

    # ─── MITRE ATT&CK ─────────────────────────────────────────────────────────
    attack_data_dir: Path = BASE_DIR / "data" / "attack"
    enterprise_attack_file: str = "enterprise-attack.json"
    ics_attack_file: str = "ics-attack.json"

    # URL resmi MITRE untuk download data ATT&CK
    enterprise_attack_url: str = (
        "https://raw.githubusercontent.com/mitre/cti/master/"
        "enterprise-attack/enterprise-attack.json"
    )
    ics_attack_url: str = (
        "https://raw.githubusercontent.com/mitre/cti/master/"
        "ics-attack/ics-attack.json"
    )

    # ─── Operational Safety ───────────────────────────────────────────────────
    # Jika True, operasi write ke OT/PLC diblokir kecuali ada izin eksplisit
    default_production_safe: bool = True

    # ─── Logging ──────────────────────────────────────────────────────────────
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_file: Path = BASE_DIR / "logs" / "aep.log"
    log_rotation: str = "10 MB"
    log_retention: str = "30 days"

    # ─── Computed Properties ──────────────────────────────────────────────────
    @property
    def enterprise_attack_path(self) -> Path:
        return self.attack_data_dir / self.enterprise_attack_file

    @property
    def ics_attack_path(self) -> Path:
        return self.attack_data_dir / self.ics_attack_file

    @property
    def has_ai_configured(self) -> bool:
        return self.anthropic_api_key is not None and len(self.anthropic_api_key) > 10

    @property
    def has_shannon_configured(self) -> bool:
        return self.shannon_api_key is not None and len(self.shannon_api_key) > 10

    @property
    def has_pentest_box_configured(self) -> bool:
        return bool(self.pentest_box_host and self.pentest_box_user)

    @field_validator("attack_data_dir", "log_file", mode="before")
    @classmethod
    def resolve_path(cls, v: str | Path) -> Path:
        return Path(v)

    def ensure_directories(self) -> None:
        """Buat direktori yang diperlukan jika belum ada."""
        self.attack_data_dir.mkdir(parents=True, exist_ok=True)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Singleton settings — cached setelah pertama kali dipanggil.
    Gunakan fungsi ini di seluruh aplikasi, bukan instantiasi langsung.
    """
    settings = Settings()
    settings.ensure_directories()
    return settings
