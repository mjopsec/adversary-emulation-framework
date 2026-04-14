"""
Report Generator — Menghasilkan laporan kampanye dalam berbagai format.

Phase 1: JSON dan teks (dasar)
Phase 5+: PDF, HTML, ATT&CK Navigator JSON, DOT graph
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from core.models.campaign import Campaign, CampaignStep
from core.models.execution import Execution
from core.models.finding import Finding


class ReportGenerator:
    """Generator laporan untuk hasil kampanye adversari emulasi."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def generate_json_report(self, campaign_id: str) -> dict[str, Any]:
        """
        Hasilkan laporan lengkap dalam format JSON.
        Format ini dapat diimport ke tools lain (Neo4j, MITRE ATT&CK Navigator, dll.).
        """
        campaign = await self._get_campaign_with_data(campaign_id)
        if not campaign:
            raise ValueError(f"Kampanye {campaign_id} tidak ditemukan.")

        executions = await self._get_executions(campaign_id)
        findings = await self._get_findings(campaign_id)

        # ─── Statistik ────────────────────────────────────────────────────────
        total_techniques = len(executions)
        detected = sum(1 for f in findings if f.detected)
        not_detected = sum(1 for f in findings if not f.detected)
        partial = sum(1 for f in findings if f.detection_quality == "partial")

        gaps_by_severity = {}
        for f in findings:
            if not f.detected:
                gaps_by_severity.setdefault(f.severity, []).append(f.technique_id)

        # ─── ATT&CK Navigator Layer ───────────────────────────────────────────
        navigator_layer = self._build_navigator_layer(campaign, findings)

        # ─── Attack Path (sederhana) ──────────────────────────────────────────
        attack_path = self._build_attack_path(campaign, executions)

        report = {
            "metadata": {
                "report_generated_at": datetime.now(timezone.utc).isoformat(),
                "platform": "AE Platform v1.0.0",
                "campaign_id": campaign_id,
            },
            "campaign": {
                "name": campaign.name,
                "client": campaign.client_name,
                "engagement_type": campaign.engagement_type,
                "environment_type": campaign.environment_type,
                "status": campaign.status,
                "started_at": campaign.started_at.isoformat() if campaign.started_at else None,
                "completed_at": campaign.completed_at.isoformat() if campaign.completed_at else None,
            },
            "summary": {
                "total_techniques_executed": total_techniques,
                "detected": detected,
                "not_detected": not_detected,
                "partial_detection": partial,
                "detection_rate_percent": round((detected / total_techniques * 100), 1) if total_techniques else 0,
                "gaps_by_severity": {k: len(v) for k, v in gaps_by_severity.items()},
            },
            "execution_history": [
                {
                    "step": idx + 1,
                    "technique_id": ex.technique_id,
                    "technique_name": ex.technique_name,
                    "target": ex.target,
                    "status": ex.status,
                    "started_at": ex.started_at.isoformat() if ex.started_at else None,
                    "duration_seconds": ex.duration_seconds,
                    "command_output": ex.result_detail,
                    "error": ex.error_message,
                }
                for idx, ex in enumerate(executions)
            ],
            "findings": [
                {
                    "technique_id": f.technique_id,
                    "technique_name": f.technique_name,
                    "severity": f.severity,
                    "detected": f.detected,
                    "detection_quality": f.detection_quality,
                    "gap_description": f.gap_description,
                    "remediation_recommendation": f.remediation_recommendation,
                    "priority_score": f.priority_score,
                    "sigma_rule": f.sigma_rule,
                    "kql_query": f.kql_query,
                }
                for f in sorted(findings, key=lambda x: x.priority_score, reverse=True)
            ],
            "attack_path": attack_path,
            "navigator_layer": navigator_layer,
        }

        return report

    async def save_json_report(self, campaign_id: str, output_dir: Path) -> Path:
        """Simpan laporan JSON ke file."""
        output_dir.mkdir(parents=True, exist_ok=True)
        report = await self.generate_json_report(campaign_id)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"report_{campaign_id[:8]}_{timestamp}.json"
        filepath = output_dir / filename

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        logger.info("Laporan JSON disimpan ke: {}", filepath)
        return filepath

    # ─── ATT&CK Navigator Layer ───────────────────────────────────────────────

    def _build_navigator_layer(
        self, campaign: Campaign, findings: list[Finding]
    ) -> dict:
        """
        Buat ATT&CK Navigator layer JSON dari hasil kampanye.
        Bisa diimport langsung ke https://mitre-attack.github.io/attack-navigator/
        """
        techniques = []
        for finding in findings:
            color = (
                "#ff0000" if finding.detected and finding.detection_quality == "full"
                else "#ff8c00" if finding.detected and finding.detection_quality == "partial"
                else "#ffffff"  # Putih = tidak terdeteksi (gap)
            )
            score = (
                100 if not finding.detected
                else 50 if finding.detection_quality == "partial"
                else 0
            )
            techniques.append({
                "techniqueID": finding.technique_id,
                "score": score,
                "color": color,
                "comment": finding.gap_description or "",
                "enabled": True,
            })

        return {
            "name": f"AEP — {campaign.name}",
            "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
            "domain": "ics-attack" if campaign.environment_type == "ot" else "enterprise-attack",
            "description": f"Hasil kampanye: {campaign.name} | Klien: {campaign.client_name}",
            "techniques": techniques,
            "gradient": {
                "colors": ["#ffffff", "#ff0000"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [
                {"label": "Tidak Terdeteksi (Gap Kritis)", "color": "#ffffff"},
                {"label": "Terdeteksi Sebagian", "color": "#ff8c00"},
                {"label": "Terdeteksi Penuh", "color": "#ff0000"},
            ],
        }

    # ─── Attack Path ──────────────────────────────────────────────────────────

    def _build_attack_path(
        self, campaign: Campaign, executions: list[Execution]
    ) -> list[dict]:
        """Buat representasi linear dari jalur serangan yang diambil."""
        return [
            {
                "step": idx + 1,
                "technique_id": ex.technique_id,
                "technique_name": ex.technique_name,
                "target": ex.target,
                "status": ex.status,
                "duration_seconds": ex.duration_seconds,
            }
            for idx, ex in enumerate(
                sorted(executions, key=lambda x: x.started_at or datetime.min)
            )
        ]

    # ─── Database Helpers ─────────────────────────────────────────────────────

    async def _get_campaign_with_data(self, campaign_id: str) -> Campaign | None:
        result = await self.session.execute(
            select(Campaign).where(Campaign.id == campaign_id)
        )
        return result.scalar_one_or_none()

    async def _get_executions(self, campaign_id: str) -> list[Execution]:
        result = await self.session.execute(
            select(Execution)
            .where(Execution.campaign_id == campaign_id)
            .order_by(Execution.started_at)
        )
        return result.scalars().all()

    async def _get_findings(self, campaign_id: str) -> list[Finding]:
        # priority_score adalah @property Python, tidak bisa dipakai di ORDER BY SQL.
        # Fetch semua findings lalu sort di Python.
        result = await self.session.execute(
            select(Finding)
            .where(Finding.campaign_id == campaign_id)
            .order_by(Finding.created_at)
        )
        findings = result.scalars().all()
        return sorted(findings, key=lambda f: f.priority_score, reverse=True)
