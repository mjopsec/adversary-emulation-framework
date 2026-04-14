"""
Purple Team Manager — Orchestrator sesi kolaborasi red + blue team.

Purple Team adalah pendekatan di mana red team (attacker simulation) dan blue team
(defender) bekerja secara transparan bersama-sama untuk:
1. Menguji apakah kontrol deteksi berfungsi sebagaimana mestinya
2. Mengidentifikasi gap yang tidak terlihat dari perspektif blue team saja
3. Meningkatkan kualitas detection rules secara iteratif
4. Mengukur MTTD (Mean Time To Detect) dan coverage

Workflow:
  1. Red team umumkan: "Saya akan jalankan T1566 sekarang"
  2. Red team eksekusi teknik
  3. Blue team merespons dalam waktu N menit
  4. Catat respons, hitung gap, generate rekomendasi
  5. Ulangi untuk setiap teknik dalam scope
  6. Generate laporan akhir dengan coverage metrics
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.detection.validator import DetectionValidator, DetectionScore
from core.models.purple_session import PurpleEvent, PurpleSession


# ─── Response Types ───────────────────────────────────────────────────────────

VALID_BLUE_RESPONSES = {
    "detected",       # SIEM/SOC mendeteksi teknik ini
    "blocked",        # EDR/firewall memblokir sebelum eksekusi
    "partial",        # Terdeteksi sebagian (misal: alert muncul tapi terlambat > 30 menit)
    "missed",         # Tidak terdeteksi sama sekali — INI GAP
    "false_positive", # Terdeteksi tapi sebagai false positive (noisy rule)
}

# Threshold waktu deteksi untuk kategorisasi
DETECTION_LATENCY_THRESHOLDS = {
    "fast": 300,       # < 5 menit = deteksi cepat (ideal)
    "medium": 1800,    # < 30 menit = masih acceptable
    "slow": 3600,      # < 1 jam = terlambat tapi masih detectable
    # > 1 jam = effectively missed untuk banyak skenario
}


@dataclass
class PurpleRecommendation:
    """Satu rekomendasi perbaikan dari hasil purple session."""
    technique_id: str
    priority: int                   # 1=urgent, 10=backlog
    title: str
    description: str
    steps: list[str] = field(default_factory=list)
    sigma_hint: str = ""
    estimated_effort: str = "medium"  # low | medium | high
    category: str = "detection"      # detection | tuning | process | tool

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "priority": self.priority,
            "title": self.title,
            "description": self.description,
            "steps": self.steps,
            "sigma_hint": self.sigma_hint,
            "estimated_effort": self.estimated_effort,
            "category": self.category,
        }


@dataclass
class PurpleSessionReport:
    """Laporan lengkap hasil purple team session."""
    session_id: str
    session_name: str
    environment: str
    status: str

    # Metrik
    total_tested: int
    detected: int
    blocked: int
    missed: int
    detection_coverage: float
    mttd_seconds: float | None

    # Analisis
    top_gaps: list[str]                         # Technique IDs dengan gap terbesar
    recommendations: list[PurpleRecommendation]
    coverage_by_tactic: dict[str, float]

    # Detail per teknik
    technique_scores: list[DetectionScore] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "session_name": self.session_name,
            "environment": self.environment,
            "status": self.status,
            "metrics": {
                "total_tested": self.total_tested,
                "detected": self.detected,
                "blocked": self.blocked,
                "missed": self.missed,
                "detection_coverage": self.detection_coverage,
                "gap_rate": round(1 - self.detection_coverage, 3),
                "mttd_seconds": self.mttd_seconds,
            },
            "top_gaps": self.top_gaps,
            "coverage_by_tactic": self.coverage_by_tactic,
            "recommendations": [r.to_dict() for r in self.recommendations],
            "techniques_tested": len(self.technique_scores),
        }


class PurpleTeamManager:
    """
    Manager untuk lifecycle purple team sessions.

    Satu instance per session, atau digunakan stateless via session_id.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.validator = DetectionValidator()

    # ─── Session Management ───────────────────────────────────────────────────

    async def create_session(
        self,
        name: str,
        environment: str = "it",
        campaign_id: str | None = None,
        description: str | None = None,
        red_team_lead: str | None = None,
        blue_team_lead: str | None = None,
        facilitator: str | None = None,
    ) -> PurpleSession:
        """Buat purple team session baru dalam status 'draft'."""
        ps = PurpleSession(
            name=name,
            environment=environment,
            campaign_id=campaign_id,
            description=description,
            red_team_lead=red_team_lead,
            blue_team_lead=blue_team_lead,
            facilitator=facilitator,
            status="draft",
        )
        self.session.add(ps)
        await self.session.commit()
        await self.session.refresh(ps)
        logger.info("Purple session dibuat: {} ({})", ps.id, name)
        return ps

    async def start_session(self, session_id: str) -> PurpleSession | None:
        """Aktivasi session — ubah status menjadi 'active'."""
        ps = await self._get_session(session_id)
        if not ps or ps.status != "draft":
            return None
        ps.status = "active"
        ps.started_at = datetime.now(timezone.utc).replace(tzinfo=None)
        await self.session.commit()
        logger.info("Purple session dimulai: {}", session_id)
        return ps

    async def complete_session(self, session_id: str) -> PurpleSession | None:
        """Selesaikan session dan hitung metrik final."""
        ps = await self._get_session(session_id)
        if not ps or ps.status not in ("active", "paused"):
            return None
        ps.status = "completed"
        ps.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
        ps.recompute_metrics()
        await self.session.commit()
        logger.info(
            "Purple session selesai: {} | coverage={:.0%} gaps={}",
            session_id, ps.detection_coverage, ps.gap_count,
        )
        return ps

    # ─── Event Recording ──────────────────────────────────────────────────────

    async def record_red_team_action(
        self,
        session_id: str,
        technique_id: str,
        technique_name: str | None = None,
        tactic: str | None = None,
        execution_method: str | None = None,
        target: str | None = None,
        notes: str | None = None,
    ) -> PurpleEvent:
        """
        Catat aksi red team (sebelum ada respons blue team).
        Menunggu blue team mengisi respons via record_blue_response().
        """
        ps = await self._get_session(session_id)
        if not ps:
            raise ValueError(f"Session {session_id} tidak ditemukan.")
        if not ps.is_active:
            raise ValueError(f"Session {session_id} tidak dalam status aktif.")

        event = PurpleEvent(
            session_id=session_id,
            technique_id=technique_id.upper(),
            technique_name=technique_name,
            tactic=tactic,
            execution_method=execution_method,
            target=target,
            red_notes=notes,
            blue_response=None,  # Menunggu respons blue team
            is_gap=False,
        )
        self.session.add(event)
        await self.session.commit()
        await self.session.refresh(event)
        logger.debug("Red team action recorded: {} untuk session {}", technique_id, session_id)
        return event

    async def record_blue_response(
        self,
        event_id: str,
        blue_response: str,
        detection_latency_seconds: float | None = None,
        detected_by: str | None = None,
        triggered_alert: str | None = None,
        notes: str | None = None,
    ) -> PurpleEvent:
        """
        Catat respons blue team untuk event tertentu.
        Secara otomatis menghitung gap severity dan generate Sigma hint.
        """
        if blue_response not in VALID_BLUE_RESPONSES:
            raise ValueError(
                f"blue_response tidak valid: '{blue_response}'. "
                f"Pilihan: {VALID_BLUE_RESPONSES}"
            )

        event_result = await self.session.execute(
            select(PurpleEvent).where(PurpleEvent.id == event_id)
        )
        event = event_result.scalar_one_or_none()
        if not event:
            raise ValueError(f"Event {event_id} tidak ditemukan.")

        # Score deteksi
        score = self.validator.score_detection(
            technique_id=event.technique_id,
            technique_name=event.technique_name or event.technique_id,
            blue_response=blue_response,
            detection_latency=detection_latency_seconds,
            detected_by=detected_by,
            triggered_alert=triggered_alert,
        )

        # Isi event dengan respons blue team
        event.blue_response = blue_response
        event.detection_latency_seconds = detection_latency_seconds
        event.detected_by = detected_by
        event.triggered_alert = triggered_alert
        event.blue_notes = notes

        # Gap analysis
        is_gap = score.is_gap
        event.is_gap = is_gap

        if is_gap:
            session_result = await self.session.execute(
                select(PurpleSession).where(PurpleSession.id == event.session_id)
            )
            ps = session_result.scalar_one_or_none()
            is_ot = ps.environment == "ot" if ps else False

            event.gap_severity = self.validator.assess_finding_severity(
                event.technique_id, blue_response, is_ot
            )
            event.gap_description = self._describe_gap(event.technique_id, blue_response)
            event.sigma_rule_hint = self.validator.generate_sigma_hint(
                event.technique_id,
                context={"execution_method": event.execution_method or ""},
            )
            event.remediation_priority = self._compute_priority(event.gap_severity)
            event.remediation_steps = self._generate_remediation_steps(
                event.technique_id, blue_response
            )

            logger.warning(
                "GAP TERIDENTIFIKASI: {} ({}) | severity={}",
                event.technique_id, event.technique_name, event.gap_severity,
            )
        else:
            logger.info(
                "Teknik {} TERDETEKSI oleh {} (response={})",
                event.technique_id, detected_by or "unknown", blue_response,
            )

        # Update metrik session
        session_result = await self.session.execute(
            select(PurpleSession).where(PurpleSession.id == event.session_id)
        )
        ps = session_result.scalar_one_or_none()
        if ps:
            ps.recompute_metrics()

        await self.session.commit()
        return event

    # ─── Reporting ────────────────────────────────────────────────────────────

    async def generate_report(self, session_id: str) -> PurpleSessionReport:
        """Generate laporan lengkap hasil purple session."""
        ps = await self._get_session(session_id)
        if not ps:
            raise ValueError(f"Session {session_id} tidak ditemukan.")

        # Kumpulkan scores dari semua events yang sudah ada respons blue team
        events_with_response = [e for e in ps.events if e.blue_response is not None]
        scores = [
            self.validator.score_detection(
                technique_id=e.technique_id,
                technique_name=e.technique_name or e.technique_id,
                blue_response=e.blue_response,
                detection_latency=e.detection_latency_seconds,
                detected_by=e.detected_by,
                triggered_alert=e.triggered_alert,
            )
            for e in events_with_response
        ]

        coverage = self.validator.compute_coverage_report(scores)

        # Generate rekomendasi untuk setiap gap
        recommendations = self._generate_recommendations(
            [e for e in events_with_response if e.is_gap]
        )

        return PurpleSessionReport(
            session_id=session_id,
            session_name=ps.name,
            environment=ps.environment,
            status=ps.status,
            total_tested=coverage.total_techniques,
            detected=coverage.detected_full,
            blocked=coverage.blocked,
            missed=coverage.not_detected,
            detection_coverage=coverage.detection_rate,
            mttd_seconds=coverage.mttd_seconds,
            top_gaps=coverage.top_gaps,
            recommendations=recommendations,
            coverage_by_tactic=coverage.coverage_by_tactic,
            technique_scores=scores,
        )

    async def get_gap_summary(self, session_id: str) -> dict:
        """Ringkasan gap untuk quick view tanpa full report."""
        ps = await self._get_session(session_id)
        if not ps:
            return {"error": "Session tidak ditemukan."}

        gaps = [e for e in ps.events if e.is_gap]
        return {
            "session_id": session_id,
            "total_gaps": len(gaps),
            "gaps": [
                {
                    "technique_id": g.technique_id,
                    "technique_name": g.technique_name,
                    "severity": g.gap_severity,
                    "description": g.gap_description,
                }
                for g in gaps
            ],
            "detection_coverage": ps.detection_coverage,
            "total_tested": ps.total_techniques_tested,
        }

    # ─── Private Helpers ──────────────────────────────────────────────────────

    async def _get_session(self, session_id: str) -> PurpleSession | None:
        result = await self.session.execute(
            select(PurpleSession).where(PurpleSession.id == session_id)
        )
        return result.scalar_one_or_none()

    def _describe_gap(self, technique_id: str, blue_response: str) -> str:
        """Buat deskripsi gap yang mudah dipahami."""
        tid = technique_id.upper()
        if blue_response == "missed":
            return (
                f"Teknik {tid} dieksekusi tanpa terdeteksi oleh stack pertahanan. "
                f"Tidak ada alert, log, atau respons dari SOC/SIEM/EDR. "
                f"Ini merupakan blind spot yang perlu segera ditangani."
            )
        elif blue_response == "false_positive":
            return (
                f"Teknik {tid} terdeteksi tapi sebagai false positive — "
                f"rule yang ada terlalu noisy dan kemungkinan diabaikan oleh analis. "
                f"Perlu tuning untuk meningkatkan signal-to-noise ratio."
            )
        return f"Teknik {tid} tidak terdeteksi secara penuh (response: {blue_response})."

    def _generate_remediation_steps(
        self, technique_id: str, blue_response: str
    ) -> list[str]:
        """Generate langkah-langkah remediasi spesifik."""
        tid = technique_id.upper()
        base_steps = [
            f"1. Review log source yang relevan untuk {tid} (lihat Sigma hint)",
            "2. Verifikasi bahwa log forwarding ke SIEM berfungsi untuk source terkait",
            "3. Deploy Sigma rule hint yang di-generate sebagai starting point",
            "4. Tune rule dengan data dari environment production selama 2 minggu",
            "5. Buat alert playbook untuk respons analis ketika rule trigger",
        ]

        if blue_response == "false_positive":
            return [
                f"1. Identifikasi pattern false positive untuk {tid}",
                "2. Tambahkan exception untuk traffic/proses yang legitimate",
                "3. Perkuat kondisi deteksi dengan filter tambahan",
                "4. Re-test setelah tuning dengan red team exercise berikutnya",
            ]

        # Tambahan untuk teknik kritikal
        if tid in ("T1003", "T0843", "T0856"):
            base_steps.append(
                f"⚡ PRIORITAS TINGGI: {tid} adalah teknik berisiko tinggi — "
                "deploy dalam 48 jam dan validasi ulang dalam sprint berikutnya."
            )

        return base_steps

    def _compute_priority(self, severity: str | None) -> int:
        """Konversi severity ke angka prioritas (1=paling urgent)."""
        return {"critical": 1, "high": 2, "medium": 4, "low": 7}.get(severity or "medium", 5)

    def _generate_recommendations(self, gap_events: list[PurpleEvent]) -> list[PurpleRecommendation]:
        """Generate rekomendasi dari list gap events."""
        recommendations = []
        for event in sorted(gap_events, key=lambda e: self._compute_priority(e.gap_severity)):
            sigma = self.validator.generate_sigma_hint(
                event.technique_id,
                context={"execution_method": event.execution_method or ""},
            )
            rec = PurpleRecommendation(
                technique_id=event.technique_id,
                priority=event.remediation_priority,
                title=f"Deploy deteksi untuk {event.technique_id} ({event.technique_name or ''})",
                description=event.gap_description or f"Gap: {event.technique_id} tidak terdeteksi.",
                steps=event.remediation_steps,
                sigma_hint=sigma,
                estimated_effort="medium" if event.gap_severity in ("critical", "high") else "low",
                category="detection",
            )
            recommendations.append(rec)
        return recommendations
