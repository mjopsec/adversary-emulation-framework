"""
Pivot Engine — Logika pivot otomatis saat teknik gagal.

Saat sebuah teknik gagal atau terdeteksi, Pivot Engine:
1. Menganalisis penyebab kegagalan (detection, permission, network, dll.)
2. Memilih teknik alternatif dari taktik yang sama atau taktik adjacent
3. Menyesuaikan context untuk teknik berikutnya berdasarkan informasi yang didapat
4. Mencatat keputusan pivot untuk audit trail

Pivot Engine bekerja bersama AIDecisionEngine dan TechniqueSelector:
- TechniqueSelector: menyediakan kandidat teknik pengganti
- AIDecisionEngine: reasoning mengapa pivot dilakukan dan apa yang dipilih
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from core.engine.ai_decision import AIDecisionEngine
from core.engine.technique_selector import TechniqueSelector
from core.techniques.base import ExecutionStatus


class FailureReason(str, Enum):
    """Klasifikasi penyebab kegagalan teknik."""
    DETECTED = "detected"               # Terdeteksi oleh blue team
    NO_PRIVILEGE = "no_privilege"       # Tidak punya izin yang cukup
    NETWORK_BLOCKED = "network_blocked" # Jaringan diblokir (firewall, dll.)
    TARGET_UNAVAILABLE = "target_unavailable"  # Target tidak merespons
    WRONG_ENVIRONMENT = "wrong_environment"    # Teknik tidak cocok dengan env
    SCOPE_VIOLATION = "scope_violation"  # Target di luar scope
    DEPENDENCY_FAILED = "dependency_failed"    # Langkah sebelumnya gagal
    UNKNOWN = "unknown"                 # Penyebab tidak diketahui


@dataclass
class PivotDecision:
    """Keputusan pivot yang diambil oleh Pivot Engine."""
    # Input
    failed_technique_id: str
    failure_reason: FailureReason
    execution_status: ExecutionStatus

    # Output
    should_pivot: bool
    pivot_technique_id: str | None = None
    pivot_tactic: str | None = None       # Taktik dari teknik pivot (bisa berbeda)
    pivot_reasoning: str = ""
    confidence: float = 0.5

    # Context adjustment yang direkomendasikan
    context_adjustments: dict[str, Any] = field(default_factory=dict)

    # Metadata
    timestamp: datetime = field(default_factory=datetime.utcnow)
    decision_log: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "failed_technique": self.failed_technique_id,
            "failure_reason": self.failure_reason.value,
            "execution_status": self.execution_status.value,
            "should_pivot": self.should_pivot,
            "pivot_technique": self.pivot_technique_id,
            "pivot_tactic": self.pivot_tactic,
            "pivot_reasoning": self.pivot_reasoning,
            "confidence": self.confidence,
            "context_adjustments": self.context_adjustments,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class PivotHistory:
    """Riwayat pivot untuk satu kampanye."""
    campaign_id: str
    pivots: list[PivotDecision] = field(default_factory=list)
    total_failures: int = 0
    total_pivots: int = 0

    def add_pivot(self, decision: PivotDecision) -> None:
        self.pivots.append(decision)
        self.total_failures += 1
        if decision.should_pivot and decision.pivot_technique_id:
            self.total_pivots += 1

    def get_pivot_rate(self) -> float:
        """Rasio teknik yang di-pivot vs total kegagalan."""
        if self.total_failures == 0:
            return 0.0
        return self.total_pivots / self.total_failures

    def was_technique_tried(self, technique_id: str) -> bool:
        """Cek apakah teknik sudah pernah dicoba (termasuk gagal)."""
        return any(p.failed_technique_id == technique_id for p in self.pivots)

    def to_summary(self) -> dict:
        return {
            "campaign_id": self.campaign_id,
            "total_failures": self.total_failures,
            "total_pivots": self.total_pivots,
            "pivot_rate": round(self.get_pivot_rate(), 2),
            "pivot_history": [p.to_dict() for p in self.pivots[-10:]],  # 10 terakhir
        }


class PivotEngine:
    """
    Engine pivot otomatis ketika teknik gagal atau terdeteksi.

    Strategi pivot (berurutan):
    1. Coba teknik alternatif dari taktik yang sama (lateral pivot)
    2. Jika tidak ada, coba dari taktik adjacent dalam kill chain (forward pivot)
    3. Jika taktik sudah completed, skip ke taktik berikutnya (skip pivot)
    4. Jika tidak ada jalan keluar, tandai kampanye perlu intervensi manual
    """

    # Taktik adjacent dalam kill chain IT (fallback ke taktik sebelah)
    IT_ADJACENT_TACTICS: dict[str, list[str]] = {
        "initial-access":      ["execution", "reconnaissance"],
        "execution":           ["initial-access", "persistence"],
        "persistence":         ["execution", "privilege-escalation"],
        "privilege-escalation": ["credential-access", "execution"],
        "defense-evasion":     ["execution", "privilege-escalation"],
        "credential-access":   ["discovery", "privilege-escalation"],
        "discovery":           ["lateral-movement", "credential-access"],
        "lateral-movement":    ["discovery", "collection"],
        "collection":          ["command-and-control", "lateral-movement"],
        "command-and-control": ["lateral-movement", "exfiltration"],
        "exfiltration":        ["collection", "impact"],
        "impact":              ["exfiltration", "collection"],
    }

    OT_ADJACENT_TACTICS: dict[str, list[str]] = {
        "initial-access":         ["execution", "discovery"],
        "execution":              ["initial-access", "persistence"],
        "persistence":            ["execution", "lateral-movement"],
        "discovery":              ["lateral-movement", "collection"],
        "lateral-movement":       ["discovery", "collection"],
        "collection":             ["command-and-control"],
        "command-and-control":    ["lateral-movement", "inhibit-response-function"],
        "inhibit-response-function": ["impair-process-control", "impact"],
        "impair-process-control": ["inhibit-response-function", "impact"],
        "impact":                 ["impair-process-control"],
    }

    # Maximum pivot attempts sebelum menyerah
    MAX_PIVOT_ATTEMPTS = 3

    def __init__(
        self,
        session: AsyncSession,
        ai_engine: AIDecisionEngine,
    ) -> None:
        self.session = session
        self.ai_engine = ai_engine
        self.selector = TechniqueSelector(session)
        self._histories: dict[str, PivotHistory] = {}

    def get_history(self, campaign_id: str) -> PivotHistory:
        """Dapatkan riwayat pivot untuk kampanye tertentu."""
        if campaign_id not in self._histories:
            self._histories[campaign_id] = PivotHistory(campaign_id=campaign_id)
        return self._histories[campaign_id]

    async def decide_pivot(
        self,
        campaign_id: str,
        failed_technique_id: str,
        current_tactic: str,
        environment: str,
        execution_result: dict,
        previously_tried: list[str] | None = None,
    ) -> PivotDecision:
        """
        Putuskan apakah perlu pivot dan ke mana.

        Args:
            campaign_id:          ID kampanye yang sedang berjalan
            failed_technique_id:  ID teknik yang gagal
            current_tactic:       Taktik saat ini
            environment:          'it' atau 'ot'
            execution_result:     Dict hasil eksekusi dari CampaignRunner
            previously_tried:     Teknik yang sudah dicoba (untuk dihindari)

        Returns:
            PivotDecision dengan rekomendasi teknik pengganti
        """
        history = self.get_history(campaign_id)
        previously_tried = previously_tried or []

        # Analisis penyebab kegagalan
        failure_reason = self._classify_failure(execution_result)
        exec_status_str = execution_result.get("status", "failed")
        exec_status = ExecutionStatus(exec_status_str) if exec_status_str in ExecutionStatus._value2member_map_ else ExecutionStatus.FAILED

        logger.info(
            "Pivot analysis: technique={} tactic={} reason={}",
            failed_technique_id, current_tactic, failure_reason.value,
        )

        # Jika scope violation atau target unavailable: tidak bisa pivot, hentikan
        if failure_reason in (FailureReason.SCOPE_VIOLATION, FailureReason.TARGET_UNAVAILABLE):
            decision = PivotDecision(
                failed_technique_id=failed_technique_id,
                failure_reason=failure_reason,
                execution_status=exec_status,
                should_pivot=False,
                pivot_reasoning=f"Tidak bisa pivot: {failure_reason.value}. Perlu intervensi manual.",
            )
            history.add_pivot(decision)
            return decision

        # Cek jumlah pivot yang sudah dilakukan untuk taktik ini
        same_tactic_pivots = sum(
            1 for p in history.pivots
            if p.pivot_tactic == current_tactic and p.should_pivot
        )
        if same_tactic_pivots >= self.MAX_PIVOT_ATTEMPTS:
            logger.warning(
                "Batas pivot ({}) untuk taktik '{}' tercapai. Skip ke taktik berikutnya.",
                self.MAX_PIVOT_ATTEMPTS, current_tactic,
            )
            # Forward pivot ke taktik adjacent
            return await self._forward_pivot(
                campaign_id=campaign_id,
                failed_technique_id=failed_technique_id,
                current_tactic=current_tactic,
                environment=environment,
                failure_reason=failure_reason,
                exec_status=exec_status,
                previously_tried=previously_tried,
                history=history,
            )

        # Lateral pivot: cari teknik alternatif dari taktik yang sama
        exclude = set(previously_tried + [failed_technique_id])
        candidates = await self.selector.get_candidates(
            tactic=current_tactic,
            environment=environment,
            limit=5,
            exclude_ids=list(exclude),
        )

        if candidates:
            best = candidates[0]
            context_adj = self._recommend_context_adjustments(failure_reason, best.technique_id)
            reasoning = await self._get_pivot_reasoning(
                failed_id=failed_technique_id,
                pivot_id=best.technique_id,
                failure_reason=failure_reason,
                tactic=current_tactic,
            )
            decision = PivotDecision(
                failed_technique_id=failed_technique_id,
                failure_reason=failure_reason,
                execution_status=exec_status,
                should_pivot=True,
                pivot_technique_id=best.technique_id,
                pivot_tactic=current_tactic,
                pivot_reasoning=reasoning,
                confidence=best.score,
                context_adjustments=context_adj,
                decision_log=[
                    f"Lateral pivot: {failed_technique_id} → {best.technique_id}",
                    f"Kandidat tersedia: {[c.technique_id for c in candidates]}",
                    f"Penyebab: {failure_reason.value}",
                ],
            )
            history.add_pivot(decision)
            logger.info(
                "Pivot decision: {} → {} (confidence={:.2f})",
                failed_technique_id, best.technique_id, best.score,
            )
            return decision

        # Tidak ada kandidat lateral, coba forward pivot
        return await self._forward_pivot(
            campaign_id=campaign_id,
            failed_technique_id=failed_technique_id,
            current_tactic=current_tactic,
            environment=environment,
            failure_reason=failure_reason,
            exec_status=exec_status,
            previously_tried=previously_tried,
            history=history,
        )

    async def _forward_pivot(
        self,
        campaign_id: str,
        failed_technique_id: str,
        current_tactic: str,
        environment: str,
        failure_reason: FailureReason,
        exec_status: ExecutionStatus,
        previously_tried: list[str],
        history: PivotHistory,
    ) -> PivotDecision:
        """Pivot ke taktik adjacent dalam kill chain."""
        adjacent_map = (
            self.OT_ADJACENT_TACTICS if environment == "ot"
            else self.IT_ADJACENT_TACTICS
        )
        adjacent_tactics = adjacent_map.get(current_tactic, [])

        for adj_tactic in adjacent_tactics:
            exclude = set(previously_tried + [failed_technique_id])
            candidates = await self.selector.get_candidates(
                tactic=adj_tactic,
                environment=environment,
                limit=3,
                exclude_ids=list(exclude),
            )
            if candidates:
                best = candidates[0]
                reasoning = (
                    f"Forward pivot dari '{current_tactic}' ke '{adj_tactic}' "
                    f"karena tidak ada kandidat lateral. "
                    f"Teknik terpilih: {best.technique_id} ({best.name})."
                )
                decision = PivotDecision(
                    failed_technique_id=failed_technique_id,
                    failure_reason=failure_reason,
                    execution_status=exec_status,
                    should_pivot=True,
                    pivot_technique_id=best.technique_id,
                    pivot_tactic=adj_tactic,
                    pivot_reasoning=reasoning,
                    confidence=best.score * 0.8,  # Sedikit kurangi confidence karena taktik berbeda
                    context_adjustments={"tactic_changed": adj_tactic},
                    decision_log=[
                        f"Forward pivot dari '{current_tactic}' ke '{adj_tactic}'",
                        f"Teknik: {best.technique_id}",
                    ],
                )
                history.add_pivot(decision)
                logger.info(
                    "Forward pivot: {} → {} (tactic: {} → {})",
                    failed_technique_id, best.technique_id, current_tactic, adj_tactic,
                )
                return decision

        # Tidak ada pivot yang memungkinkan
        logger.warning(
            "Tidak ada pivot yang memungkinkan untuk teknik {} di taktik '{}'.",
            failed_technique_id, current_tactic,
        )
        decision = PivotDecision(
            failed_technique_id=failed_technique_id,
            failure_reason=failure_reason,
            execution_status=exec_status,
            should_pivot=False,
            pivot_reasoning=(
                "Tidak ada teknik pengganti yang tersedia. "
                "Langkah ini harus dilewati atau memerlukan intervensi manual."
            ),
            decision_log=["No candidates found in lateral or forward tactics."],
        )
        history.add_pivot(decision)
        return decision

    def _classify_failure(self, execution_result: dict) -> FailureReason:
        """Klasifikasi penyebab kegagalan dari hasil eksekusi."""
        status = execution_result.get("status", "failed")
        error = (execution_result.get("result_detail") or "").lower()
        detected = execution_result.get("detected", False)

        if status == "aborted":
            if "scope" in error:
                return FailureReason.SCOPE_VIOLATION
            return FailureReason.WRONG_ENVIRONMENT

        if detected:
            return FailureReason.DETECTED

        # Analisis pesan error
        if any(kw in error for kw in ("privilege", "administrator", "elevation", "access denied")):
            return FailureReason.NO_PRIVILEGE
        if any(kw in error for kw in ("network", "connection", "timeout", "refused", "firewall")):
            return FailureReason.NETWORK_BLOCKED
        if any(kw in error for kw in ("tidak tersedia", "unavailable", "offline", "unreachable")):
            return FailureReason.TARGET_UNAVAILABLE

        return FailureReason.UNKNOWN

    def _recommend_context_adjustments(
        self, failure_reason: FailureReason, next_technique_id: str
    ) -> dict[str, Any]:
        """Rekomendasikan penyesuaian context untuk teknik berikutnya."""
        adjustments: dict[str, Any] = {}

        if failure_reason == FailureReason.DETECTED:
            adjustments["use_obfuscation"] = True
            adjustments["delay_between_actions"] = True
            adjustments["stealth_mode"] = True

        elif failure_reason == FailureReason.NO_PRIVILEGE:
            adjustments["check_privileges"] = True
            adjustments["requires_elevation"] = True

        elif failure_reason == FailureReason.NETWORK_BLOCKED:
            adjustments["try_alternative_ports"] = True
            adjustments["use_encrypted_channel"] = True

        return adjustments

    async def _get_pivot_reasoning(
        self,
        failed_id: str,
        pivot_id: str,
        failure_reason: FailureReason,
        tactic: str,
    ) -> str:
        """Dapatkan reasoning pivot dari AI atau gunakan fallback."""
        fallback = (
            f"Teknik {failed_id} gagal ({failure_reason.value}). "
            f"Pivot ke {pivot_id} yang menggunakan pendekatan berbeda "
            f"untuk mencapai tujuan taktik '{tactic}' yang sama."
        )

        if not self.ai_engine._ai_available:
            return fallback

        try:
            prompt = (
                f"Dalam skenario red team authorized, teknik ATT&CK {failed_id} gagal "
                f"dengan alasan: {failure_reason.value}. "
                f"Jelaskan dalam 1-2 kalimat mengapa pivot ke {pivot_id} adalah pilihan tepat "
                f"untuk melanjutkan tujuan taktik '{tactic}'."
            )
            return await self.ai_engine._call_ai(prompt)
        except Exception:
            return fallback

    async def analyze_campaign_pivots(self, campaign_id: str) -> dict:
        """Analisis pola pivot dalam satu kampanye untuk insight."""
        history = self.get_history(campaign_id)
        summary = history.to_summary()

        # Analisis pattern
        if history.total_failures == 0:
            summary["insight"] = "Tidak ada kegagalan — semua teknik berhasil dieksekusi."
        elif history.get_pivot_rate() > 0.7:
            summary["insight"] = (
                "Tingkat pivot tinggi — kemungkinan blue team memiliki deteksi yang kuat "
                "atau ada masalah privileges/network di lingkungan target."
            )
        else:
            summary["insight"] = (
                f"Kampanye berjalan dengan {history.total_pivots} pivot dari {history.total_failures} kegagalan "
                f"({summary['pivot_rate']*100:.0f}% pivot rate)."
            )

        # Failure reason distribution
        reason_counts: dict[str, int] = {}
        for pivot in history.pivots:
            r = pivot.failure_reason.value
            reason_counts[r] = reason_counts.get(r, 0) + 1
        summary["failure_distribution"] = reason_counts

        return summary
