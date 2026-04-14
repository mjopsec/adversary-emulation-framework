"""
Technique Registry — Sistem pendaftaran dan penemuan teknik serangan.

Registry berfungsi sebagai pusat katalog semua teknik yang dapat dieksekusi.
Teknik didaftarkan dengan decorator @register_technique dan dapat ditemukan
berdasarkan ATT&CK ID, taktik, atau lingkungan (IT/OT).

Desain: Singleton registry yang auto-discover teknik dari sub-modul
saat pertama kali diakses.
"""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from core.techniques.base import BaseTechnique


class TechniqueRegistry:
    """
    Registry tunggal (singleton) untuk semua implementasi BaseTechnique.

    Penggunaan:
        registry = TechniqueRegistry.instance()
        technique = registry.get("T1566")
        all_it = registry.list_by_environment("it")
    """

    _instance: "TechniqueRegistry | None" = None
    _discovered: bool = False

    def __init__(self) -> None:
        # technique_id → class (belum di-instantiate)
        self._registry: dict[str, type["BaseTechnique"]] = {}

    @classmethod
    def instance(cls) -> "TechniqueRegistry":
        """Kembalikan singleton instance, discover teknik jika belum."""
        if cls._instance is None:
            cls._instance = cls()
        if not cls._discovered:
            # Set True SEBELUM discover untuk mencegah rekursi:
            # @register_technique memanggil instance() saat modul di-import,
            # yang akan memicu discover_all() lagi jika flag belum diset.
            cls._discovered = True
            cls._instance.discover_all()
        return cls._instance

    # ─── Registration ─────────────────────────────────────────────────────────

    def register(self, technique_class: type["BaseTechnique"]) -> None:
        """Daftarkan satu kelas teknik ke registry."""
        tid = technique_class.technique_id
        if not tid:
            logger.warning("Teknik {} tidak memiliki technique_id, diabaikan.", technique_class.__name__)
            return
        if tid in self._registry:
            logger.debug("Teknik {} sudah terdaftar, mengganti dengan {}.", tid, technique_class.__name__)
        self._registry[tid] = technique_class
        logger.debug("Teknik terdaftar: {} ({})", tid, technique_class.__name__)

    def discover_all(self) -> None:
        """
        Auto-discover semua teknik dari sub-modul it/ dan ot/.
        Import setiap modul agar decorator @register_technique berjalan.
        """
        base_path = Path(__file__).parent
        packages_to_scan = ["core.techniques.it", "core.techniques.ot"]

        total = 0
        for package_name in packages_to_scan:
            try:
                package = importlib.import_module(package_name)
                package_path = Path(package.__file__).parent
                for _, module_name, _ in pkgutil.iter_modules([str(package_path)]):
                    full_name = f"{package_name}.{module_name}"
                    try:
                        importlib.import_module(full_name)
                        total += 1
                    except Exception as e:
                        logger.warning("Gagal import modul teknik {}: {}", full_name, e)
            except Exception as e:
                logger.warning("Gagal scan package {}: {}", package_name, e)

        logger.info(
            "Technique discovery selesai: {} modul di-scan, {} teknik terdaftar.",
            total, len(self._registry),
        )

    # ─── Lookup ───────────────────────────────────────────────────────────────

    def get(self, technique_id: str) -> "BaseTechnique | None":
        """Kembalikan instance teknik berdasarkan ATT&CK ID. None jika tidak ada."""
        cls = self._registry.get(technique_id.upper())
        if cls is None:
            return None
        return cls()

    def get_class(self, technique_id: str) -> "type[BaseTechnique] | None":
        """Kembalikan class teknik (belum di-instantiate)."""
        return self._registry.get(technique_id.upper())

    def list_all(self) -> list[str]:
        """Daftar semua technique ID yang terdaftar."""
        return sorted(self._registry.keys())

    def list_by_environment(self, environment: str) -> list[str]:
        """Filter teknik berdasarkan lingkungan: 'it', 'ot', atau 'both'."""
        from core.techniques.base import Environment
        result = []
        for tid, cls in self._registry.items():
            envs = cls.supported_environments
            if environment == "both":
                result.append(tid)
            elif any(e.value == environment or e.value == "both" for e in envs):
                result.append(tid)
        return sorted(result)

    def list_by_tactic(self, tactic: str) -> list[str]:
        """Filter teknik berdasarkan taktik ATT&CK."""
        return sorted(
            tid for tid, cls in self._registry.items()
            if getattr(cls, "tactic", "").lower() == tactic.lower()
        )

    def list_by_risk(self, max_risk: str) -> list[str]:
        """Filter teknik dengan risk level di bawah atau sama dengan max_risk."""
        risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        max_val = risk_order.get(max_risk, 99)
        return sorted(
            tid for tid, cls in self._registry.items()
            if risk_order.get(cls.risk_level, 0) <= max_val
        )

    def count(self) -> int:
        return len(self._registry)

    def info(self) -> dict:
        """Ringkasan registry untuk health check dan debugging."""
        it_count = len(self.list_by_environment("it"))
        ot_count = len(self.list_by_environment("ot"))
        return {
            "total": self.count(),
            "it_techniques": it_count,
            "ot_techniques": ot_count,
            "technique_ids": self.list_all(),
        }

    def __repr__(self) -> str:
        return f"<TechniqueRegistry count={self.count()}>"


# ─── Decorator untuk registrasi otomatis ──────────────────────────────────────

def register_technique(cls: type["BaseTechnique"]) -> type["BaseTechnique"]:
    """
    Class decorator untuk mendaftarkan teknik ke registry global.

    Penggunaan:
        @register_technique
        class PhishingTechnique(BaseTechnique):
            technique_id = "T1566"
            ...
    """
    TechniqueRegistry.instance().register(cls)
    return cls
