"""
Detection Validator — Analisis dan validasi kualitas deteksi untuk setiap teknik.

Fungsi utama:
1. Score detection quality (none / partial / full) berdasarkan respons blue team
2. Generate Sigma rule hint untuk teknik yang tidak terdeteksi
3. Bangun detection coverage report untuk satu kampanye
4. Hitung MTTD (Mean Time To Detect) dari riwayat deteksi

Sigma rule format yang di-generate adalah hint template — bukan rule siap pakai.
Blue team perlu menyesuaikan dengan environment dan log source masing-masing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from loguru import logger


# ─── Detection Scoring ────────────────────────────────────────────────────────

class DetectionQuality:
    NONE = "none"
    PARTIAL = "partial"
    FULL = "full"


@dataclass
class DetectionScore:
    """Skor deteksi satu teknik."""
    technique_id: str
    technique_name: str
    quality: str                    # none | partial | full
    confidence: float               # 0.0–1.0
    latency_seconds: float | None   # Waktu sampai terdeteksi
    detected_by: str | None         # Tool yang mendeteksi
    triggered_alert: str | None     # Alert/rule yang trigger
    false_positive_risk: str        # low | medium | high
    notes: str = ""

    @property
    def is_gap(self) -> bool:
        return self.quality == DetectionQuality.NONE

    @property
    def severity(self) -> str:
        """Severity dari detection gap (semakin tidak terdeteksi = semakin severe)."""
        if self.quality == DetectionQuality.NONE:
            return "high"
        if self.quality == DetectionQuality.PARTIAL:
            return "medium"
        return "low"    # Full detection = low severity finding


@dataclass
class CoverageReport:
    """Laporan coverage deteksi untuk satu kampanye atau purple session."""
    total_techniques: int
    detected_full: int
    detected_partial: int
    not_detected: int
    blocked: int

    technique_scores: list[DetectionScore] = field(default_factory=list)
    mttd_seconds: float | None = None           # Mean Time To Detect
    top_gaps: list[str] = field(default_factory=list)  # Technique IDs dengan gap terbesar
    coverage_by_tactic: dict[str, float] = field(default_factory=dict)

    @property
    def detection_rate(self) -> float:
        """Rasio teknik yang berhasil dideteksi (full atau partial)."""
        if self.total_techniques == 0:
            return 0.0
        return round((self.detected_full + self.detected_partial + self.blocked) / self.total_techniques, 3)

    @property
    def gap_rate(self) -> float:
        if self.total_techniques == 0:
            return 0.0
        return round(self.not_detected / self.total_techniques, 3)

    def to_dict(self) -> dict:
        return {
            "total_techniques": self.total_techniques,
            "detected_full": self.detected_full,
            "detected_partial": self.detected_partial,
            "not_detected": self.not_detected,
            "blocked": self.blocked,
            "detection_rate": self.detection_rate,
            "gap_rate": self.gap_rate,
            "mttd_seconds": self.mttd_seconds,
            "top_gaps": self.top_gaps,
            "coverage_by_tactic": self.coverage_by_tactic,
        }


# ─── Sigma Rule Generator ─────────────────────────────────────────────────────

# Template Sigma rule hints per teknik ATT&CK
SIGMA_TEMPLATES: dict[str, dict] = {
    "T1566": {
        "title": "Suspicious Phishing Email Attachment",
        "logsource": {"category": "email", "product": "mail_server"},
        "detection_keywords": ["attachment_type: exe,vbs,js,docm,xlsm", "external_sender"],
        "references": ["https://attack.mitre.org/techniques/T1566/"],
        "fp_note": "Internal attachments with same extension — check sender domain",
    },
    "T1059": {
        "title": "Suspicious Command Interpreter Execution",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_keywords": [
            "CommandLine|contains: '-EncodedCommand'",
            "CommandLine|contains: 'IEX'",
            "CommandLine|contains: 'Invoke-Expression'",
            "Image|endswith: 'powershell.exe'",
        ],
        "references": ["https://attack.mitre.org/techniques/T1059/"],
        "fp_note": "Many legitimate admin scripts use PowerShell — baseline first",
    },
    "T1078": {
        "title": "Valid Account Usage Outside Business Hours",
        "logsource": {"category": "authentication", "product": "windows"},
        "detection_keywords": [
            "EventID: 4624",
            "LogonType: 3",
            "TimeCreated|outside: '08:00-18:00'",
        ],
        "references": ["https://attack.mitre.org/techniques/T1078/"],
        "fp_note": "Adjust hours to business hours for your org",
    },
    "T1021": {
        "title": "Suspicious Remote Service Access",
        "logsource": {"category": "network_connection", "product": "sysmon"},
        "detection_keywords": [
            "DestinationPort: 3389|445|5985|5986",
            "Initiated: true",
            "Image|not_contains: known_rdp_clients",
        ],
        "references": ["https://attack.mitre.org/techniques/T1021/"],
        "fp_note": "Whitelist known IT admin hosts",
    },
    "T1003": {
        "title": "Credential Dumping Attempt",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection_keywords": [
            "Image|endswith: 'mimikatz.exe'",
            "CommandLine|contains: 'sekurlsa'",
            "CommandLine|contains: 'lsadump'",
            "TargetImage|endswith: 'lsass.exe'",
        ],
        "references": ["https://attack.mitre.org/techniques/T1003/"],
        "fp_note": "LSASS access by non-system processes is rare — high confidence",
    },
    "T1071": {
        "title": "Suspicious C2 Communication over Application Protocol",
        "logsource": {"category": "network_connection", "product": "firewall"},
        "detection_keywords": [
            "dst_port: 443|80|53",
            "bytes_out|greater: 500000",
            "connection_frequency|greater: 60_per_hour",
        ],
        "references": ["https://attack.mitre.org/techniques/T1071/"],
        "fp_note": "Beaconing pattern (regular interval) is key indicator",
    },
    "T0801": {
        "title": "ICS Process State Monitoring (Unauthorized Read)",
        "logsource": {"category": "ics_network", "product": "modbus"},
        "detection_keywords": [
            "function_code: 1|2|3|4",
            "src_ip|not_in: authorized_scada_servers",
            "timestamp|outside: maintenance_window",
        ],
        "references": ["https://attack.mitre.org/techniques/T0801/"],
        "fp_note": "Compare against authorized SCADA/HMI IP list",
    },
    "T0843": {
        "title": "Unauthorized PLC Program Download",
        "logsource": {"category": "ics_network", "product": "s7comm"},
        "detection_keywords": [
            "function: download_program|upload_program",
            "src_ip|not_in: authorized_engineering_stations",
        ],
        "references": ["https://attack.mitre.org/techniques/T0843/"],
        "fp_note": "Only authorized engineering workstations should connect to PLC",
    },
    "T0856": {
        "title": "ICS Data Spoofing via Replay Attack",
        "logsource": {"category": "ics_network"},
        "detection_keywords": [
            "packet_similarity|greater: 0.95",
            "timestamp_gap|less: 1ms",
            "value_sequence: repeated",
        ],
        "references": ["https://attack.mitre.org/techniques/T0856/"],
        "fp_note": "Replay detection requires baseline of normal value distributions",
    },
    "T0869": {
        "title": "Covert OT C2 via Standard Application Protocol",
        "logsource": {"category": "ics_network", "product": "modbus"},
        "detection_keywords": [
            "coil_write|to: reserved_registers",
            "register_value|anomaly: true",
            "write_frequency: unusual",
        ],
        "references": ["https://attack.mitre.org/techniques/T0869/"],
        "fp_note": "Requires behavioral baseline of normal register write patterns",
    },
}

# Default template untuk teknik tanpa template spesifik
DEFAULT_SIGMA_TEMPLATE: dict = {
    "title": "ATT&CK Technique Execution — Generic",
    "logsource": {"category": "process_creation", "product": "windows"},
    "detection_keywords": [
        "# Sesuaikan dengan artifact yang ditinggalkan teknik ini",
        "# Periksa CommandLine, Image, dan registry untuk IOCs",
    ],
    "fp_note": "Perlu tuning berdasarkan environment spesifik",
}


class DetectionValidator:
    """
    Validator untuk kualitas deteksi teknik ATT&CK.

    Digunakan oleh:
    - Purple Team session saat blue team memberikan respons
    - Campaign runner setelah eksekusi teknik
    - Reporting engine untuk compute coverage metrics
    """

    def score_detection(
        self,
        technique_id: str,
        technique_name: str,
        blue_response: str,
        detection_latency: float | None = None,
        detected_by: str | None = None,
        triggered_alert: str | None = None,
    ) -> DetectionScore:
        """
        Hitung skor deteksi berdasarkan respons blue team.

        blue_response options:
          detected       → full detection (terdeteksi oleh SOC/SIEM)
          blocked        → blocked sebelum eksekusi (EDR/firewall)
          partial        → sebagian terdeteksi (misal: detected tapi terlambat)
          missed         → tidak terdeteksi sama sekali (GAP!)
          false_positive → terdeteksi tapi sebagai false positive
        """
        quality_map = {
            "detected": DetectionQuality.FULL,
            "blocked": DetectionQuality.FULL,
            "partial": DetectionQuality.PARTIAL,
            "false_positive": DetectionQuality.PARTIAL,  # Detected but noisy
            "missed": DetectionQuality.NONE,
        }
        quality = quality_map.get(blue_response, DetectionQuality.NONE)

        # Confidence lebih tinggi jika ada informasi spesifik
        confidence = 0.9 if detected_by and triggered_alert else (
            0.7 if detected_by or triggered_alert else 0.5
        )
        if blue_response == "missed":
            confidence = 1.0  # 100% confident ini adalah gap

        # False positive risk
        fp_risk = "high" if blue_response == "false_positive" else (
            "medium" if quality == DetectionQuality.PARTIAL else "low"
        )

        return DetectionScore(
            technique_id=technique_id.upper(),
            technique_name=technique_name,
            quality=quality,
            confidence=confidence,
            latency_seconds=detection_latency,
            detected_by=detected_by,
            triggered_alert=triggered_alert,
            false_positive_risk=fp_risk,
        )

    def generate_sigma_hint(self, technique_id: str, context: dict | None = None) -> str:
        """
        Generate Sigma rule hint YAML untuk teknik yang tidak terdeteksi.

        Ini adalah template/hint, bukan Sigma rule yang production-ready.
        Blue team perlu menyesuaikan dengan log source dan environment mereka.
        """
        tid = technique_id.upper()
        template = SIGMA_TEMPLATES.get(tid, DEFAULT_SIGMA_TEMPLATE)
        context = context or {}

        detection_lines = "\n".join(
            f"        - {kw}" for kw in template.get("detection_keywords", [])
        )
        refs = template.get("references", [f"https://attack.mitre.org/techniques/{tid}/"])
        refs_lines = "\n".join(f"    - {r}" for r in refs)

        logsource = template.get("logsource", {})
        ls_lines = "\n".join(f"    {k}: {v}" for k, v in logsource.items())

        execution_method = context.get("execution_method", "")
        method_note = f"\n    # Method: {execution_method}" if execution_method else ""

        yaml_hint = f"""title: {template['title']}
id: aep-hint-{tid.lower()}
status: experimental
description: >
    [AEP HINT] Detection rule hint untuk {tid}.
    Sesuaikan threshold, log source, dan kondisi dengan environment Anda.
    FALSE POSITIVE NOTE: {template.get('fp_note', 'Perlu tuning.')}
references:
{refs_lines}
author: AEP Platform (auto-generated hint)
date: auto
tags:
    - attack.{tid.lower()}
logsource:
{ls_lines}
detection:{method_note}
    keywords:
{detection_lines}
    condition: keywords
falsepositives:
    - {template.get('fp_note', 'Legitimate admin activity — requires tuning')}
level: high
"""
        return yaml_hint.strip()

    def compute_coverage_report(self, scores: list[DetectionScore]) -> CoverageReport:
        """Hitung laporan coverage dari daftar DetectionScore."""
        if not scores:
            return CoverageReport(0, 0, 0, 0, 0)

        full = sum(1 for s in scores if s.quality == DetectionQuality.FULL and not s.false_positive_risk == "high")
        partial = sum(1 for s in scores if s.quality == DetectionQuality.PARTIAL)
        missed = sum(1 for s in scores if s.quality == DetectionQuality.NONE)
        blocked = sum(1 for s in scores if s.detected_by and "block" in (s.detected_by or "").lower())

        # MTTD hanya dari teknik yang berhasil dideteksi dengan latency data
        latencies = [s.latency_seconds for s in scores if s.latency_seconds is not None]
        mttd = round(sum(latencies) / len(latencies), 1) if latencies else None

        # Top gaps: teknik tidak terdeteksi diurutkan berdasarkan nama
        top_gaps = [s.technique_id for s in scores if s.is_gap]

        # Coverage by tactic (menggunakan prefix teknik sebagai proxy)
        tactic_scores: dict[str, list[bool]] = {}
        for s in scores:
            # Untuk simplisitas, kelompokkan berdasarkan huruf pertama ID (T1xxx vs T0xxx)
            prefix = "ot" if s.technique_id.startswith("T0") else "it"
            if prefix not in tactic_scores:
                tactic_scores[prefix] = []
            tactic_scores[prefix].append(not s.is_gap)

        coverage_by_tactic = {
            env: round(sum(vals) / len(vals), 3) if vals else 0.0
            for env, vals in tactic_scores.items()
        }

        return CoverageReport(
            total_techniques=len(scores),
            detected_full=full,
            detected_partial=partial,
            not_detected=missed,
            blocked=blocked,
            technique_scores=scores,
            mttd_seconds=mttd,
            top_gaps=top_gaps,
            coverage_by_tactic=coverage_by_tactic,
        )

    def assess_finding_severity(
        self,
        technique_id: str,
        blue_response: str,
        is_ot_environment: bool = False,
    ) -> str:
        """Tentukan severity finding berdasarkan teknik dan status deteksi."""
        if blue_response != "missed":
            return "low" if blue_response == "detected" else "medium"

        # Missed detection — severity berdasarkan teknik
        high_impact_it = {"T1003", "T1021", "T1059", "T1071", "T1078"}
        critical_ot = {"T0843", "T0856", "T0869"}

        tid = technique_id.upper()
        if is_ot_environment and tid in critical_ot:
            return "critical"
        if tid in high_impact_it:
            return "high"
        return "medium"
