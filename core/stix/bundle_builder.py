"""
STIX Bundle Builder — Orkestrasi pembuatan bundle STIX 2.1 dari data AEP.

Tiga jenis bundle:
  1. campaign_bundle()      — Campaign + AttackPatterns + Findings + Relationships
  2. purple_bundle()        — PurpleSession gaps sebagai Indicators + CourseOfActions
  3. technique_bundle()     — Satu teknik ATT&CK sebagai AttackPattern standalone
"""

from __future__ import annotations

import json
from typing import Any

from stix2 import Bundle

from core.stix.mapper import STIXMapper


# ─── Campaign Bundle ──────────────────────────────────────────────────────────

def build_campaign_bundle(report_data: dict) -> Bundle:
    """
    Buat STIX bundle dari JSON report kampanye (output ReportGenerator.generate_json_report()).

    Objek yang dihasilkan:
    - Identity (AEP)
    - Campaign (STIX)
    - AttackPattern per teknik unik
    - Indicator per gap dengan sigma rule
    - CourseOfAction per finding dengan remediation
    - Relationship: Campaign → uses → AttackPattern
    - Relationship: Indicator → indicates → AttackPattern
    - Relationship: CourseOfAction → mitigates → AttackPattern
    """
    mapper = STIXMapper()

    campaign_meta = report_data.get("campaign", {})
    findings = report_data.get("findings", [])
    attack_path = report_data.get("attack_path", [])
    metadata = report_data.get("metadata", {})

    # ── STIX Campaign ──────────────────────────────────────────────────────
    camp = mapper.campaign_to_stix(
        campaign_id=metadata.get("campaign_id", "unknown"),
        name=campaign_meta.get("name", "Unknown Campaign"),
        description=(
            f"Client: {campaign_meta.get('client', '?')} | "
            f"Environment: {campaign_meta.get('environment_type', '?')} | "
            f"Engagement: {campaign_meta.get('engagement_type', '?')}"
        ),
        first_seen=_parse_dt(campaign_meta.get("started_at")),
        last_seen=_parse_dt(campaign_meta.get("completed_at")),
    )

    # ── AttackPatterns dari execution timeline ─────────────────────────────
    # Kumpulkan tactic per technique_id dari attack_path (tidak ada di findings)
    technique_tactic: dict[str, str] = {}
    for step in attack_path:
        tid = step.get("technique_id", "")
        if tid and tid not in technique_tactic:
            technique_tactic[tid] = ""  # tactic not available in attack_path

    # Buat AttackPattern + relasi Campaign → uses → AttackPattern
    ap_by_tid: dict[str, Any] = {}
    for tid, tactic in technique_tactic.items():
        name = next(
            (f.get("technique_name") for f in findings if f.get("technique_id") == tid),
            None,
        )
        ap = mapper.technique_to_attack_pattern(tid, name, tactic or None)
        ap_by_tid[tid] = ap
        mapper.add_relationship(camp, "uses", ap)

    # ── Findings → Indicators + CourseOfActions ────────────────────────────
    for finding in findings:
        tid = finding.get("technique_id", "")
        if not tid:
            continue

        # Pastikan AttackPattern ada (teknik dari findings yang tidak ada di path)
        if tid not in ap_by_tid:
            ap = mapper.technique_to_attack_pattern(
                tid,
                finding.get("technique_name"),
                tactic=None,
            )
            ap_by_tid[tid] = ap
            mapper.add_relationship(camp, "uses", ap)

        ap = ap_by_tid[tid]

        # Indicator untuk gaps
        if not finding.get("detected"):
            ind = mapper.finding_to_indicator(
                technique_id=tid,
                technique_name=finding.get("technique_name"),
                sigma_rule=finding.get("sigma_rule"),
                kql_query=finding.get("kql_query"),
                severity=finding.get("severity", "medium"),
            )
            if ind:
                mapper.add_relationship(ind, "indicates", ap)

        # CourseOfAction untuk remediasi
        remediation = finding.get("remediation_recommendation")
        if remediation:
            coa = mapper.remediation_to_course_of_action(tid, remediation)
            mapper.add_relationship(coa, "mitigates", ap)

    return mapper.build_bundle()


# ─── Purple Team Bundle ───────────────────────────────────────────────────────

def build_purple_bundle(report_dict: dict) -> Bundle:
    """
    Buat STIX bundle dari laporan purple team (output PurpleSessionReport.to_dict()).

    Fokus pada detection gaps:
    - AttackPattern per teknik yang di-test
    - Indicator per gap (missed detection) dengan Sigma hints
    - CourseOfAction dari rekomendasi
    - Relationship: Indicator → indicates → AttackPattern
    - Relationship: CourseOfAction → mitigates → AttackPattern
    """
    mapper = STIXMapper()

    events = report_dict.get("events", [])
    recommendations = report_dict.get("recommendations", [])

    # Map technique_id → recommendation steps untuk CourseOfAction
    rec_by_tid: dict[str, list[str]] = {}
    for rec in recommendations:
        tid = rec.get("technique_id", "")
        if tid:
            rec_by_tid[tid] = rec.get("steps", [])

    # ── AttackPatterns + Indicators per event ─────────────────────────────
    ap_by_tid: dict[str, Any] = {}
    for event in events:
        tid = event.get("technique_id", "")
        if not tid:
            continue

        if tid not in ap_by_tid:
            ap = mapper.technique_to_attack_pattern(
                tid,
                event.get("technique_name"),
                tactic=event.get("tactic"),
            )
            ap_by_tid[tid] = ap

        ap = ap_by_tid[tid]

        # Indicator hanya untuk gaps (missed/false_positive)
        if event.get("is_gap"):
            ind = mapper.finding_to_indicator(
                technique_id=tid,
                technique_name=event.get("technique_name"),
                sigma_rule=event.get("sigma_rule_hint"),
                severity=event.get("gap_severity", "medium"),
            )
            if ind:
                mapper.add_relationship(ind, "indicates", ap)

        # CourseOfAction dari rekomendasi
        if tid in rec_by_tid:
            steps_text = "\n".join(f"- {s}" for s in rec_by_tid[tid])
            coa = mapper.remediation_to_course_of_action(tid, steps_text)
            mapper.add_relationship(coa, "mitigates", ap)

    return mapper.build_bundle()


# ─── Single Technique Bundle ──────────────────────────────────────────────────

def build_technique_bundle(
    technique_id: str,
    technique_name: str | None = None,
    tactic: str | None = None,
    description: str | None = None,
) -> Bundle:
    """
    Buat STIX bundle sederhana dari satu teknik ATT&CK.
    Berguna untuk lookup / sharing satu teknik ke MISP/OpenCTI.
    """
    mapper = STIXMapper()
    mapper.technique_to_attack_pattern(technique_id, technique_name, tactic, description)
    return mapper.build_bundle()


# ─── Helpers ──────────────────────────────────────────────────────────────────

def bundle_to_dict(bundle: Bundle) -> dict:
    """Konversi bundle ke plain dict (JSON-serializable)."""
    return json.loads(bundle.serialize())


def _parse_dt(value: str | None):
    """Parse ISO datetime string ke datetime object, atau None."""
    if not value:
        return None
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None
