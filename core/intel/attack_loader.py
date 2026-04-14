"""
MITRE ATT&CK Data Loader.

Memuat dan mem-parsing data ATT&CK dari file STIX 2.1 lokal.
Mendukung Enterprise ATT&CK (IT) dan ICS ATT&CK (OT).
Data di-download otomatis dari GitHub MITRE jika belum ada di lokal.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from core.config import Settings


# ─── Dataclass untuk representasi teknik yang di-parse ────────────────────────

@dataclass
class ParsedTechnique:
    """Representasi sementara teknik ATT&CK sebelum disimpan ke database."""
    technique_id: str
    name: str
    description: str
    tactic: str           # Taktik utama (pertama dalam daftar)
    tactics: list[str]    # Semua taktik
    platforms: list[str]
    environment: str      # "it" atau "ot"
    is_subtechnique: bool
    parent_technique_id: str | None
    detection_note: str
    data_sources: list[str]
    mitigation_note: str
    risk_level: str
    destructive: bool
    requires_explicit_approval: bool
    stix_id: str
    attack_url: str


# ─── ATT&CK Loader Class ──────────────────────────────────────────────────────

class ATTACKLoader:
    """
    Loader untuk data MITRE ATT&CK dalam format STIX 2.1.

    Workflow:
    1. Cek apakah file STIX sudah ada di lokal
    2. Jika tidak, download dari MITRE GitHub (dengan konfirmasi)
    3. Parse objek technique dan tactic dari STIX bundle
    4. Simpan ke database via bulk insert
    """

    # Teknik OT yang berpotensi destruktif (memerlukan approval eksplisit)
    DESTRUCTIVE_TECHNIQUES = {
        "T0813", "T0814", "T0816", "T0826", "T0828",
        "T0829", "T0831", "T0837", "T0838", "T0839",
        "T0840", "T0841", "T0843", "T0879",
    }

    # Taktik ICS ATT&CK → kategori risiko
    ICS_HIGH_RISK_TACTICS = {
        "impair-process-control",
        "inhibit-response-function",
        "impact",
    }

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._enterprise_data: dict | None = None
        self._ics_data: dict | None = None

    # ─── Data Loading ─────────────────────────────────────────────────────────

    async def ensure_data_available(self, auto_download: bool = True) -> dict[str, bool]:
        """
        Pastikan data ATT&CK tersedia secara lokal.
        Kembalikan status ketersediaan untuk setiap domain.
        """
        status = {
            "enterprise": self.settings.enterprise_attack_path.exists(),
            "ics": self.settings.ics_attack_path.exists(),
        }

        if not status["enterprise"] and auto_download:
            logger.info("Enterprise ATT&CK data tidak ditemukan, memulai download...")
            await self._download_file(
                self.settings.enterprise_attack_url,
                self.settings.enterprise_attack_path,
                "Enterprise ATT&CK",
            )
            status["enterprise"] = True

        if not status["ics"] and auto_download:
            logger.info("ICS ATT&CK data tidak ditemukan, memulai download...")
            await self._download_file(
                self.settings.ics_attack_url,
                self.settings.ics_attack_path,
                "ICS ATT&CK",
            )
            status["ics"] = True

        return status

    async def _download_file(self, url: str, dest: Path, label: str) -> None:
        """Download file dari URL ke path tujuan dengan progress logging."""
        dest.parent.mkdir(parents=True, exist_ok=True)

        logger.info("Downloading {} dari {}...", label, url)
        async with httpx.AsyncClient(timeout=300.0, follow_redirects=True) as client:
            async with client.stream("GET", url) as response:
                response.raise_for_status()
                total = int(response.headers.get("content-length", 0))
                downloaded = 0

                with open(dest, "wb") as f:
                    async for chunk in response.aiter_bytes(chunk_size=8192):
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total:
                            pct = (downloaded / total) * 100
                            if downloaded % (1024 * 1024) < 8192:  # Log tiap ~1MB
                                logger.debug("{}: {:.1f}% ({:.1f} MB)", label, pct, downloaded / 1e6)

        logger.info("{} berhasil didownload ke {}", label, dest)

    def _load_stix_file(self, path: Path) -> dict:
        """Load dan parse file STIX JSON dari disk."""
        logger.info("Memuat STIX data dari {}...", path)
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        logger.info(
            "STIX bundle dimuat: {} objek ditemukan",
            len(data.get("objects", []))
        )
        return data

    # ─── Parsing ──────────────────────────────────────────────────────────────

    def _extract_external_id(self, obj: dict) -> str | None:
        """Ekstrak ATT&CK ID (T1234 / T1234.001) dari external_references."""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") in ("mitre-attack", "mitre-ics-attack"):
                return ref.get("external_id")
        return None

    def _extract_url(self, obj: dict) -> str | None:
        """Ekstrak URL halaman ATT&CK dari external_references."""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") in ("mitre-attack", "mitre-ics-attack"):
                return ref.get("url")
        return None

    def _extract_tactics(self, obj: dict) -> list[str]:
        """Ekstrak daftar taktik dari kill_chain_phases."""
        return [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if "phase_name" in phase
        ]

    def _assess_risk(self, tech_id: str, tactics: list[str], environment: str) -> str:
        """Tentukan level risiko teknik berdasarkan ID dan taktiknya."""
        if tech_id in self.DESTRUCTIVE_TECHNIQUES:
            return "critical"
        if environment == "ot" and any(t in self.ICS_HIGH_RISK_TACTICS for t in tactics):
            return "high"
        high_risk_tactics = {"credential_access", "impact", "exfiltration", "lateral_movement"}
        if any(t.replace("-", "_") in high_risk_tactics for t in tactics):
            return "high"
        medium_risk_tactics = {"execution", "persistence", "privilege_escalation", "defense_evasion"}
        if any(t.replace("-", "_") in medium_risk_tactics for t in tactics):
            return "medium"
        return "low"

    def parse_enterprise_techniques(self) -> list[ParsedTechnique]:
        """Parse semua teknik dari Enterprise ATT&CK STIX bundle."""
        if self._enterprise_data is None:
            self._enterprise_data = self._load_stix_file(self.settings.enterprise_attack_path)
        return self._parse_techniques(self._enterprise_data, environment="it")

    def parse_ics_techniques(self) -> list[ParsedTechnique]:
        """Parse semua teknik dari ICS ATT&CK STIX bundle."""
        if self._ics_data is None:
            self._ics_data = self._load_stix_file(self.settings.ics_attack_path)
        return self._parse_techniques(self._ics_data, environment="ot")

    def _parse_techniques(
        self, stix_data: dict, environment: str
    ) -> list[ParsedTechnique]:
        """
        Parse objek attack-pattern dari STIX bundle menjadi ParsedTechnique.
        Mengabaikan teknik yang sudah deprecated/revoked.
        """
        objects = stix_data.get("objects", [])
        techniques = []
        skipped = 0

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                skipped += 1
                continue

            tech_id = self._extract_external_id(obj)
            if not tech_id:
                continue

            tactics = self._extract_tactics(obj)
            if not tactics:
                continue

            is_subtechnique = "." in tech_id
            parent_id = tech_id.split(".")[0] if is_subtechnique else None

            description = obj.get("description", "")
            # Batasi panjang deskripsi (STIX bisa sangat verbose)
            if len(description) > 5000:
                description = description[:5000] + "..."

            detection = obj.get("x_mitre_detection", "")
            platforms = obj.get("x_mitre_platforms", [])
            data_sources = obj.get("x_mitre_data_sources", [])

            risk = self._assess_risk(tech_id, tactics, environment)
            is_destructive = tech_id in self.DESTRUCTIVE_TECHNIQUES
            needs_approval = is_destructive or environment == "ot"

            techniques.append(ParsedTechnique(
                technique_id=tech_id,
                name=obj.get("name", ""),
                description=description,
                tactic=tactics[0],
                tactics=tactics,
                platforms=platforms,
                environment=environment,
                is_subtechnique=is_subtechnique,
                parent_technique_id=parent_id,
                detection_note=detection,
                data_sources=data_sources,
                mitigation_note="",
                risk_level=risk,
                destructive=is_destructive,
                requires_explicit_approval=needs_approval,
                stix_id=obj.get("id", ""),
                attack_url=self._extract_url(obj) or "",
            ))

        logger.info(
            "Parsed {} teknik {} ATT&CK ({} skipped karena deprecated/revoked)",
            len(techniques), environment.upper(), skipped,
        )
        return techniques

    # ─── Database Sync ────────────────────────────────────────────────────────

    async def sync_to_database(self, session: AsyncSession) -> dict[str, int]:
        """
        Sinkronisasi teknik ATT&CK ke database.
        Melakukan upsert: update jika sudah ada, insert jika belum.

        Returns: dict dengan jumlah teknik yang diinsert dan diupdate.
        """
        from core.models.technique import Technique

        all_techniques: list[ParsedTechnique] = []

        if self.settings.enterprise_attack_path.exists():
            all_techniques.extend(self.parse_enterprise_techniques())
        else:
            logger.warning("Enterprise ATT&CK file tidak ditemukan, melewati IT techniques.")

        if self.settings.ics_attack_path.exists():
            all_techniques.extend(self.parse_ics_techniques())
        else:
            logger.warning("ICS ATT&CK file tidak ditemukan, melewati OT techniques.")

        if not all_techniques:
            logger.warning("Tidak ada teknik yang di-parse. Pastikan data ATT&CK tersedia.")
            return {"inserted": 0, "updated": 0}

        # Ambil semua ID yang sudah ada di database
        existing_ids_result = await session.execute(
            select(Technique.id)
        )
        existing_ids = set(existing_ids_result.scalars().all())

        inserted = 0
        updated = 0

        for parsed in all_techniques:
            import json

            technique_data = {
                "id": parsed.technique_id,
                "name": parsed.name,
                "description": parsed.description,
                "tactic": parsed.tactic,
                "_tactics": json.dumps(parsed.tactics),
                "_platforms": json.dumps(parsed.platforms),
                "environment": parsed.environment,
                "is_subtechnique": parsed.is_subtechnique,
                "parent_technique_id": parsed.parent_technique_id,
                "detection_note": parsed.detection_note,
                "_data_sources": json.dumps(parsed.data_sources),
                "mitigation_note": parsed.mitigation_note,
                "risk_level": parsed.risk_level,
                "destructive": parsed.destructive,
                "requires_explicit_approval": parsed.requires_explicit_approval,
                "stix_id": parsed.stix_id,
                "attack_url": parsed.attack_url,
            }

            if parsed.technique_id in existing_ids:
                technique = await session.get(Technique, parsed.technique_id)
                if technique:
                    for key, value in technique_data.items():
                        setattr(technique, key, value)
                    updated += 1
            else:
                technique = Technique(**technique_data)
                session.add(technique)
                inserted += 1

        await session.commit()
        logger.info(
            "ATT&CK sync selesai: {} teknik diinsert, {} diupdate",
            inserted, updated,
        )
        return {"inserted": inserted, "updated": updated}


async def get_attack_loader(settings: Settings) -> ATTACKLoader:
    """Factory function untuk ATTACKLoader."""
    return ATTACKLoader(settings)
