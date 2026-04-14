"""
Campaign Builder — Auto-generate kampanye dari objectives + APT profile menggunakan AI.

Builder mengintegrasikan:
1. TechniqueSelector untuk memilih teknik optimal per taktik
2. AIDecisionEngine untuk reasoning dan penjelasan setiap langkah
3. APT profile database untuk menyesuaikan TTP (Tactics, Techniques, Procedures)
4. Kill chain sequencing untuk urutan yang logis

Output: Campaign siap eksekusi lengkap dengan ordered steps dan AI reasoning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import Settings
from core.engine.ai_decision import AIDecisionEngine
from core.engine.technique_selector import (
    TechniqueSelector,
    IT_TACTIC_SEQUENCE,
    OT_TACTIC_SEQUENCE,
)
from core.models.apt_profile import APTProfile


@dataclass
class BuilderConfig:
    """Konfigurasi untuk auto-campaign builder."""
    environment: str = "it"             # it | ot | hybrid_it_ot
    objectives: list[str] = field(default_factory=list)
    apt_profile_id: str | None = None
    max_risk: str = "high"             # low | medium | high | critical
    max_steps: int = 12                # Maksimum langkah yang di-generate
    prefer_registered: bool = True     # Prioritaskan teknik yang ada implementasinya
    include_alternatives: bool = True   # Sertakan teknik alternatif per fase
    min_score_threshold: float = 0.10  # Skor minimum untuk dimasukkan ke chain


@dataclass
class GeneratedStep:
    """Satu langkah yang di-generate oleh builder."""
    order_index: int
    phase: str                         # Taktik ATT&CK
    technique_id: str
    technique_name: str
    risk_level: str
    score: float
    is_implemented: bool               # Ada implementasi di registry
    ai_reasoning: str = ""
    estimated_success_rate: float = 0.5
    fallback_technique_id: str | None = None
    alternatives: list[dict] = field(default_factory=list)
    method_hint: str | None = None     # Saran metode eksekusi spesifik


@dataclass
class GeneratedCampaign:
    """Kampanye lengkap yang di-generate oleh builder."""
    name: str
    description: str
    environment: str
    objectives: list[str]
    steps: list[GeneratedStep]
    apt_profile_name: str | None = None
    apt_profile_id: str | None = None
    total_steps: int = 0
    implemented_steps: int = 0         # Langkah dengan implementasi konkret
    estimated_duration_hours: float = 0.0
    risk_summary: dict[str, int] = field(default_factory=dict)
    ai_overview: str = ""              # Narasi singkat dari AI

    def __post_init__(self) -> None:
        self.total_steps = len(self.steps)
        self.implemented_steps = sum(1 for s in self.steps if s.is_implemented)
        self.risk_summary = self._compute_risk_summary()
        self.estimated_duration_hours = len(self.steps) * 1.5  # Rata-rata 1.5 jam/langkah

    def _compute_risk_summary(self) -> dict[str, int]:
        summary: dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for step in self.steps:
            summary[step.risk_level] = summary.get(step.risk_level, 0) + 1
        return summary

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "environment": self.environment,
            "objectives": self.objectives,
            "apt_profile": self.apt_profile_name,
            "apt_profile_id": self.apt_profile_id,
            "total_steps": self.total_steps,
            "implemented_steps": self.implemented_steps,
            "implementation_coverage": (
                self.implemented_steps / self.total_steps
                if self.total_steps > 0 else 0.0
            ),
            "estimated_duration_hours": self.estimated_duration_hours,
            "risk_summary": self.risk_summary,
            "ai_overview": self.ai_overview,
            "steps": [
                {
                    "order": s.order_index + 1,
                    "phase": s.phase,
                    "technique_id": s.technique_id,
                    "technique_name": s.technique_name,
                    "risk_level": s.risk_level,
                    "score": s.score,
                    "is_implemented": s.is_implemented,
                    "ai_reasoning": s.ai_reasoning,
                    "estimated_success_rate": s.estimated_success_rate,
                    "fallback": s.fallback_technique_id,
                    "alternatives": s.alternatives,
                    "method_hint": s.method_hint,
                }
                for s in self.steps
            ],
        }

    def to_campaign_steps_create(self) -> list[dict]:
        """Konversi ke format CampaignStepCreate yang bisa disimpan ke DB."""
        return [
            {
                "order_index": s.order_index,
                "phase": s.phase,
                "technique_id": s.technique_id,
                "risk_assessment": s.risk_level,
                "ai_reasoning": s.ai_reasoning,
                "estimated_success_rate": s.estimated_success_rate,
                "fallback_action": s.fallback_technique_id,
                "notes": f"Auto-generated | Score: {s.score:.2f} | Alt: {[a['id'] for a in s.alternatives]}",
                "method": s.method_hint,
            }
            for s in self.steps
        ]


class CampaignBuilder:
    """
    Auto-Campaign Builder: hasilkan kampanye siap eksekusi dari objectives.

    Workflow:
    1. Load APT profile (jika ada) untuk mendapat preferensi TTP
    2. Filter taktik berdasarkan objectives menggunakan TechniqueSelector
    3. Untuk setiap taktik, minta TechniqueSelector memilih kandidat teknik
    4. Gunakan AIDecisionEngine untuk reasoning tiap langkah (opsional)
    5. Susun langkah dalam urutan kill chain yang logis
    6. Generate overview narasi dari AI
    """

    def __init__(
        self,
        session: AsyncSession,
        settings: Settings,
        ai_engine: AIDecisionEngine,
    ) -> None:
        self.session = session
        self.settings = settings
        self.ai_engine = ai_engine
        self.selector = TechniqueSelector(session)

    async def build(
        self,
        campaign_name: str,
        config: BuilderConfig,
        campaign_description: str | None = None,
    ) -> GeneratedCampaign:
        """
        Build kampanye lengkap berdasarkan konfigurasi.

        Args:
            campaign_name:        Nama kampanye
            config:               Konfigurasi builder
            campaign_description: Deskripsi opsional

        Returns:
            GeneratedCampaign dengan steps yang sudah diurutkan
        """
        logger.info(
            "Memulai auto-build kampanye '{}' | env={} objectives={} apt={}",
            campaign_name, config.environment, config.objectives, config.apt_profile_id,
        )

        # 1. Load APT profile
        apt_profile = await self._load_apt_profile(config.apt_profile_id)
        apt_preferred_ids = self._extract_apt_techniques(apt_profile)
        apt_name = apt_profile.name if apt_profile else None

        # 2. Pilih urutan taktik
        tactic_sequence = self._select_tactics(config)
        logger.debug("Taktik yang akan digunakan: {}", tactic_sequence)

        # 3. Generate steps untuk setiap taktik
        steps: list[GeneratedStep] = []
        exclude_used: list[str] = []

        for order_idx, tactic in enumerate(tactic_sequence):
            if len(steps) >= config.max_steps:
                logger.debug("Batas maksimum {} langkah tercapai.", config.max_steps)
                break

            candidates = await self.selector.get_candidates(
                tactic=tactic,
                environment=config.environment,
                apt_preferred_ids=apt_preferred_ids,
                max_risk=config.max_risk,
                limit=5,
                exclude_ids=exclude_used,
            )

            if not candidates:
                logger.debug("Tidak ada kandidat untuk taktik '{}', dilewati.", tactic)
                continue

            best = candidates[0]
            if best.score < config.min_score_threshold:
                logger.debug(
                    "Skor tertinggi untuk '{}' ({:.2f}) di bawah threshold, dilewati.",
                    tactic, best.score,
                )
                continue

            # Cari fallback
            fallback_id = None
            if len(candidates) > 1:
                fallback_id = candidates[1].technique_id

            # Alternatives (langkah ke-2 dan ke-3)
            alternatives = [
                {"id": c.technique_id, "name": c.name}
                for c in candidates[1:3]
            ]

            # AI reasoning (jika tersedia, jika tidak pakai deterministik)
            reasoning, success_rate, method_hint = await self._get_ai_reasoning(
                tactic=tactic,
                technique=best,
                apt_name=apt_name,
                environment=config.environment,
                step_number=len(steps) + 1,
                objectives=config.objectives,
            )

            step = GeneratedStep(
                order_index=len(steps),
                phase=tactic,
                technique_id=best.technique_id,
                technique_name=best.name,
                risk_level=best.risk_level,
                score=best.score,
                is_implemented=best.is_registered,
                ai_reasoning=reasoning,
                estimated_success_rate=success_rate,
                fallback_technique_id=fallback_id,
                alternatives=alternatives,
                method_hint=method_hint,
            )
            steps.append(step)
            exclude_used.append(best.technique_id)

        # 4. Generate AI overview
        ai_overview = await self._generate_overview(
            campaign_name=campaign_name,
            environment=config.environment,
            objectives=config.objectives,
            apt_name=apt_name,
            steps=steps,
        )

        generated = GeneratedCampaign(
            name=campaign_name,
            description=campaign_description or self._auto_description(config, apt_name),
            environment=config.environment,
            objectives=config.objectives,
            steps=steps,
            apt_profile_name=apt_name,
            apt_profile_id=config.apt_profile_id,
            ai_overview=ai_overview,
        )

        logger.info(
            "Campaign build selesai: {} langkah ({} dengan implementasi), est. {} jam",
            generated.total_steps,
            generated.implemented_steps,
            generated.estimated_duration_hours,
        )
        return generated

    # ─── Private Helpers ──────────────────────────────────────────────────────

    async def _load_apt_profile(self, profile_id: str | None) -> APTProfile | None:
        """Load APT profile dari database."""
        if not profile_id:
            return None
        result = await self.session.execute(
            select(APTProfile).where(APTProfile.id == profile_id)
        )
        profile = result.scalar_one_or_none()
        if not profile:
            logger.warning("APT profile '{}' tidak ditemukan.", profile_id)
        return profile

    def _extract_apt_techniques(self, profile: APTProfile | None) -> list[str]:
        """Ekstrak daftar teknik yang disukai dari APT profile."""
        if not profile:
            return []
        try:
            prefs = profile.technique_preferences
            if isinstance(prefs, list):
                return [str(t) for t in prefs]
            if isinstance(prefs, dict):
                return list(prefs.keys())
            return []
        except Exception:
            return []

    def _select_tactics(self, config: BuilderConfig) -> list[str]:
        """Pilih dan filter taktik berdasarkan environment dan objectives."""
        sequence = (
            OT_TACTIC_SEQUENCE
            if config.environment in ("ot",)
            else IT_TACTIC_SEQUENCE
        )

        # Gunakan method dari TechniqueSelector untuk filter berdasarkan objectives
        if config.objectives:
            filtered = self.selector._filter_tactics_by_objectives(
                sequence, config.objectives
            )
            return filtered if filtered else sequence

        # Default: ambil 8 taktik utama jika tidak ada objectives spesifik
        default_tactics = [
            "initial-access", "execution", "persistence",
            "credential-access", "discovery", "lateral-movement",
            "command-and-control", "impact",
        ]
        return [t for t in sequence if t in default_tactics]

    async def _get_ai_reasoning(
        self,
        tactic: str,
        technique: Any,
        apt_name: str | None,
        environment: str,
        step_number: int,
        objectives: list[str],
    ) -> tuple[str, float, str | None]:
        """
        Dapatkan reasoning dari AI untuk pemilihan teknik ini.
        Returns: (reasoning, success_rate, method_hint)
        """
        # Fallback deterministik
        fallback_reasoning = (
            f"Teknik {technique.technique_id} ({technique.name}) dipilih untuk fase '{tactic}' "
            f"berdasarkan skor relevansi {technique.score:.2f}. "
            f"{'Implementasi konkret tersedia.' if technique.is_registered else 'Akan menggunakan simulasi.'}"
        )

        if not self.ai_engine._ai_available:
            return (
                fallback_reasoning,
                0.65 if technique.is_registered else 0.45,
                None,
            )

        # AI reasoning (panggil hanya jika API tersedia)
        try:
            prompt = (
                f"Dalam kampanye red team authorized (lingkungan: {environment}), "
                f"langkah {step_number} menggunakan teknik {technique.technique_id} - {technique.name} "
                f"untuk fase '{tactic}'. "
                f"APT yang disimulasikan: {apt_name or 'Custom'}. "
                f"Tujuan kampanye: {', '.join(objectives)}. "
                f"Berikan dalam 1-2 kalimat:\n"
                f"1. Alasan teknik ini dipilih untuk fase ini\n"
                f"2. Estimasi probabilitas sukses (0.0-1.0)\n"
                f"3. Saran metode implementasi spesifik (opsional)\n"
                f"Format: {{\"reasoning\": \"...\", \"success_rate\": 0.0, \"method\": \"...atau null\"}}"
            )
            response = await self.ai_engine._call_ai(prompt)
            data = self.ai_engine._parse_json_response(response)
            return (
                data.get("reasoning", fallback_reasoning),
                float(data.get("success_rate", 0.6)),
                data.get("method"),
            )
        except Exception as e:
            logger.debug("AI reasoning error untuk {}: {}", technique.technique_id, e)
            return (fallback_reasoning, 0.6, None)

    async def _generate_overview(
        self,
        campaign_name: str,
        environment: str,
        objectives: list[str],
        apt_name: str | None,
        steps: list[GeneratedStep],
    ) -> str:
        """Generate narasi overview kampanye."""
        fallback = (
            f"Kampanye '{campaign_name}' dirancang untuk mengemulasi ancaman "
            f"{'OT/ICS' if environment == 'ot' else 'IT Enterprise'} "
            f"menggunakan {len(steps)} teknik ATT&CK. "
            f"Tujuan: {', '.join(objectives) or 'full kill chain'}. "
            f"{f'APT yang disimulasikan: {apt_name}.' if apt_name else ''}"
        )

        if not self.ai_engine._ai_available or not steps:
            return fallback

        try:
            technique_ids = [s.technique_id for s in steps]
            prompt = (
                f"Buat ringkasan singkat (2-3 kalimat) untuk kampanye red team authorized:\n"
                f"- Nama: {campaign_name}\n"
                f"- Lingkungan: {environment}\n"
                f"- APT: {apt_name or 'Custom'}\n"
                f"- Tujuan: {', '.join(objectives)}\n"
                f"- Teknik: {technique_ids}\n"
                f"Tuliskan untuk briefing tim red team (bukan laporan eksekutif)."
            )
            return await self.ai_engine._call_ai(prompt)
        except Exception:
            return fallback

    @staticmethod
    def _auto_description(config: BuilderConfig, apt_name: str | None) -> str:
        """Buat deskripsi otomatis dari konfigurasi."""
        env_label = {
            "it": "Enterprise IT",
            "ot": "ICS/OT",
            "hybrid": "Hybrid IT/OT",
            "hybrid_it_ot": "Hybrid IT/OT",
        }.get(config.environment, config.environment)

        parts = [f"Auto-generated {env_label} campaign"]
        if apt_name:
            parts.append(f"| APT: {apt_name}")
        if config.objectives:
            parts.append(f"| Objectives: {', '.join(config.objectives)}")
        parts.append(f"| Max risk: {config.max_risk}")
        return " ".join(parts)
