"""
Campaign Runner — Orkestrator eksekusi kampanye end-to-end.

Mengelola lifecycle kampanye:
1. Validasi konteks engagement
2. Iterasi melalui langkah-langkah kampanye
3. Koordinasi antara AI Decision Engine dan Technique Executor
4. Pencatatan eksekusi dan temuan ke database
5. Trigger pivot otomatis jika langkah gagal
"""

from datetime import datetime, timezone
from typing import AsyncGenerator

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from core.config import Settings
from core.engine.ai_decision import AIDecisionEngine, DecisionContext
from core.models.campaign import Campaign, CampaignStep
from core.models.execution import Execution
from core.models.finding import Finding


class CampaignRunner:
    """
    Orkestrator utama eksekusi kampanye.

    Dirancang untuk digunakan baik secara programatik maupun
    melalui API endpoint (streaming progress via Server-Sent Events).
    """

    def __init__(
        self,
        settings: Settings,
        ai_engine: AIDecisionEngine,
        session: AsyncSession,
    ) -> None:
        self.settings = settings
        self.ai_engine = ai_engine
        self.session = session

    async def validate_and_start(self, campaign_id: str) -> dict:
        """
        Validasi kampanye dan ubah status ke 'validating' lalu 'active'.

        Returns dict dengan status validasi dan pesan.
        """
        campaign = await self._get_campaign(campaign_id)
        if not campaign:
            return {"success": False, "error": f"Kampanye {campaign_id} tidak ditemukan."}

        if campaign.status not in ("draft", "paused"):
            return {
                "success": False,
                "error": f"Kampanye tidak bisa dimulai dari status '{campaign.status}'.",
            }

        # Validasi konteks engagement dengan AI
        campaign.status = "validating"
        await self.session.commit()

        campaign_dict = {
            "name": campaign.name,
            "client_name": campaign.client_name,
            "engagement_type": campaign.engagement_type,
            "environment_type": campaign.environment_type,
            "target_ips": campaign.target_ips,
            "target_domains": campaign.target_domains,
            "excluded_targets": campaign.excluded_targets,
            "rules_of_engagement": campaign.rules_of_engagement,
            "emergency_contact": campaign.emergency_contact,
            "start_date": campaign.start_date.isoformat() if campaign.start_date else None,
            "end_date": campaign.end_date.isoformat() if campaign.end_date else None,
            "objectives": campaign.objectives,
        }

        validation = await self.ai_engine.validate_engagement_context(campaign_dict)

        if not validation.is_valid:
            campaign.status = "draft"
            await self.session.commit()
            return {
                "success": False,
                "error": "Validasi engagement gagal.",
                "missing_fields": validation.missing_fields,
                "warnings": validation.warnings,
                "summary": validation.validation_summary,
            }

        # Aktifkan kampanye
        campaign.status = "active"
        campaign.context_validated = True
        campaign.started_at = datetime.now(timezone.utc)
        await self.session.commit()

        logger.info(
            "Kampanye '{}' (ID: {}) berhasil divalidasi dan diaktifkan.",
            campaign.name, campaign_id,
        )

        return {
            "success": True,
            "campaign_id": campaign_id,
            "warnings": validation.warnings,
            "recommendations": validation.recommendations,
            "summary": validation.validation_summary,
        }

    async def run_step(
        self,
        campaign_id: str,
        step_id: str,
        target: str,
        extra_context: dict | None = None,
    ) -> dict:
        """
        Eksekusi satu langkah kampanye.

        Urutan dispatch:
        1. Agent aktif di target IP → route ke agent (real/near-real execution)
        2. Registry implementation → simulasi konkret berbasis Python class
        3. Shannon AI → simulasi cerdas dengan output realistis

        Returns dict hasil eksekusi yang bisa di-serialize ke JSON.
        """

        campaign = await self._get_campaign(campaign_id)
        if not campaign:
            return {"success": False, "error": "Kampanye tidak ditemukan."}

        # Auto-activate jika masih draft/paused — izinkan run step langsung
        if campaign.status in ("draft", "paused", "validating"):
            campaign.status = "active"
            campaign.context_validated = True
            if not campaign.started_at:
                campaign.started_at = datetime.now(timezone.utc)
            await self.session.commit()
            logger.info("Campaign {} auto-activated untuk run step.", campaign_id)
        elif campaign.status in ("aborted", "completed"):
            return {"success": False, "error": f"Kampanye sudah {campaign.status}, tidak bisa run step."}

        # Ambil step — eager load technique untuk nama
        from sqlalchemy.orm import selectinload
        step_result = await self.session.execute(
            select(CampaignStep)
            .options(selectinload(CampaignStep.technique))
            .where(CampaignStep.id == step_id)
        )
        step = step_result.scalar_one_or_none()
        if not step:
            return {"success": False, "error": f"Step {step_id} tidak ditemukan."}

        technique_name = (
            step.technique.name if step.technique else None
        ) or step.technique_id

        # Buat record eksekusi
        execution = Execution(
            campaign_id=campaign_id,
            step_id=step_id,
            technique_id=step.technique_id,
            technique_name=technique_name,
            target=target,
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        self.session.add(execution)
        step.status = "in_progress"
        await self.session.commit()

        logger.info(
            "Menjalankan step [{}/{}]: {} → {}",
            step.order_index + 1,
            "?",
            step.technique_id,
            target,
        )

        # ─── EKSEKUSI VIA TASK DISPATCHER ────────────────────────────────────
        # Dispatcher menentukan: agent (jika aktif di target) → registry → Shannon AI
        from core.agent.task_dispatcher import TaskDispatcher

        dispatcher = TaskDispatcher(self.session)
        dispatch_result = await dispatcher.dispatch(
            technique_id=step.technique_id,
            target_ip=target,
            campaign_id=campaign_id,
            scope_ips=campaign.target_ips,
            scope_domains=campaign.target_domains,
            excluded_targets=campaign.excluded_targets,
            production_safe_mode=campaign.production_safe_mode,
            extra_context=extra_context or {},
            prefer_agent=True,
        )

        exec_status = dispatch_result.status.value
        exec_detail = dispatch_result.output or dispatch_result.error
        exec_artifacts = dispatch_result.artifacts
        next_hints = []
        collected = dispatch_result.collected_data

        logger.info(
            "Step {} selesai via {}: status={}",
            step.technique_id, dispatch_result.dispatched_via, exec_status,
        )

        # Update execution record
        execution.status = exec_status
        execution.result_detail = exec_detail
        execution.artifacts_created = exec_artifacts
        execution.completed_at = datetime.now(timezone.utc)
        execution.duration_seconds = execution.compute_duration()
        step.status = "completed" if exec_status == "success" else "failed"
        await self.session.commit()

        # Analisis hasil dengan AI dan buat finding
        analysis = await self.ai_engine.analyze_execution_result(
            technique_id=step.technique_id,
            technique_name=technique_name,
            target=target,
            execution_status=exec_status,
            result_detail=exec_detail or "",
            campaign_context={
                "name": campaign.name,
                "environment_type": campaign.environment_type,
                "objectives": campaign.objectives,
                "collected_data": collected,
            },
        )

        # Buat finding dari analisis AI
        finding = Finding(
            campaign_id=campaign_id,
            execution_id=execution.id,
            technique_id=step.technique_id,
            technique_name=execution.technique_name,
            detected=analysis["detection_analysis"]["detected"],
            detection_quality=analysis["detection_analysis"]["detection_quality"],
            severity=analysis.get("severity", "medium"),
            gap_description=analysis.get("gap_description"),
            sigma_rule=analysis.get("sigma_rule_hint"),
        )
        self.session.add(finding)
        await self.session.commit()

        return {
            "success": True,
            "execution_id": execution.id,
            "finding_id": finding.id,
            "status": execution.status,
            "result_detail": execution.result_detail,
            "detected": finding.detected,
            "severity": finding.severity,
            "next_recommended_technique": analysis.get("next_recommended_technique"),
            "should_pivot": analysis.get("should_pivot", False),
            "next_step_hints": next_hints,
            "collected_data_keys": list(collected.keys()),
            "artifacts_created": exec_artifacts,
            "dispatched_via": dispatch_result.dispatched_via,
        }

    async def abort_campaign(self, campaign_id: str, reason: str = "") -> bool:
        """Hentikan kampanye dan tandai sebagai aborted."""
        campaign = await self._get_campaign(campaign_id)
        if not campaign:
            return False

        campaign.status = "aborted"
        campaign.completed_at = datetime.now(timezone.utc)

        # Abort semua running executions
        running_result = await self.session.execute(
            select(Execution).where(
                Execution.campaign_id == campaign_id,
                Execution.status == "running",
            )
        )
        for execution in running_result.scalars().all():
            execution.status = "aborted"
            execution.error_message = f"Kampanye dihentikan: {reason}"
            execution.completed_at = datetime.now(timezone.utc)

        await self.session.commit()
        logger.warning("Kampanye {} diabort. Alasan: {}", campaign_id, reason or "tidak disebutkan")
        return True

    # ─── Private Helpers ──────────────────────────────────────────────────────

    async def _get_campaign(self, campaign_id: str) -> Campaign | None:
        result = await self.session.execute(
            select(Campaign).where(Campaign.id == campaign_id)
        )
        return result.scalar_one_or_none()

    async def _simulate_execution(
        self,
        step: CampaignStep,
        target: str,
        campaign: Campaign,
    ) -> dict:
        """
        Simulasi eksekusi teknik (Phase 1 placeholder).
        Di Phase 2+, ini akan memanggil agent yang di-deploy di target.
        """
        # Simulasi berdasarkan risk level dan environment
        # Probabilitas sukses sederhana untuk simulasi
        success_prob = {
            "low": 0.85,
            "medium": 0.65,
            "high": 0.45,
            "critical": 0.25,
        }.get(step.risk_assessment, 0.5)

        import random
        succeeded = random.random() < success_prob

        return {
            "status": "success" if succeeded else "failed",
            "result_detail": (
                f"[SIMULATION] Teknik {step.technique_id} {'berhasil dieksekusi' if succeeded else 'gagal'} "
                f"pada target {target}. "
                f"Risk level: {step.risk_assessment}. "
                f"Catatan: Ini adalah simulasi Phase 1 — implementasi agent nyata ada di Phase 4."
            ),
        }
