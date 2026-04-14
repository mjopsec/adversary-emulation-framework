"""
T0856 — Spoof Reporting Message (ICS/OT — Impair Process Control)

Simulasi manipulasi pesan pelaporan dari field device ke SCADA/Historian.
Teknik ini menyembunyikan kondisi berbahaya dari operator dengan
mengirimkan nilai sensor palsu yang terlihat normal.

Contoh nyata: Stuxnet menyembunyikan getaran sentrifugal yang abnormal
dari sistem monitoring selama berbulan-bulan dengan memutar ulang
rekaman pembacaan sensor normal.
"""

from core.techniques.base import (
    BaseTechnique,
    Environment,
    ExecutionStatus,
    TechniqueContext,
    TechniqueResult,
)
from core.techniques.registry import register_technique


@register_technique
class SpoofReportingTechnique(BaseTechnique):
    """
    Simulasi spoofing pesan sensor/status ke sistem SCADA.

    Efek: Operator melihat nilai normal di HMI padahal
    kondisi fisik aktual sedang berbahaya.
    """

    technique_id = "T0856"
    name = "Spoof Reporting Message"
    description = (
        "Adversari menyebabkan controller mengirimkan laporan yang menipu "
        "ke sistem monitoring. Operator tidak bisa melihat kondisi proses yang sebenarnya."
    )
    supported_environments = [Environment.OT]
    risk_level = "high"
    is_destructive = True   # Operator kehilangan visibilitas — berbahaya untuk produksi
    requires_elevated_privileges = False
    tactic = "impair-process-control"

    SPOOF_METHODS = {
        "replay_attack": {
            "description": "Rekam traffic normal dan putar ulang untuk menyembunyikan kondisi berbahaya",
            "detection_risk": 0.25,
            "duration": "unlimited",
            "complexity": "medium",
        },
        "mitm_modification": {
            "description": "Man-in-the-Middle antara PLC dan SCADA — modifikasi nilai secara real-time",
            "detection_risk": 0.30,
            "duration": "unlimited",
            "complexity": "high",
        },
        "plc_logic_modification": {
            "description": "Modifikasi logika PLC untuk mengirimkan nilai yang di-hardcode ke SCADA",
            "detection_risk": 0.20,
            "duration": "permanent until patched",
            "complexity": "very_high",
        },
        "rtu_tampering": {
            "description": "Manipulasi RTU untuk scaling nilai sensor sebelum dikirim ke SCADA",
            "detection_risk": 0.15,
            "duration": "unlimited",
            "complexity": "medium",
        },
    }

    # Skenario spoofing yang disimulasikan
    SPOOF_SCENARIOS = [
        {
            "tag": "TIC-101", "real_value": 280.5, "unit": "°C",
            "spoofed_value": 145.3, "real_status": "CRITICAL_HIGH",
            "spoofed_status": "NORMAL",
            "impact": "Operator tidak tahu reaktor dalam kondisi overheat",
        },
        {
            "tag": "PIC-202", "real_value": 18.9, "unit": "bar",
            "spoofed_value": 6.0, "real_status": "HIGH_HIGH_ALARM",
            "spoofed_status": "NORMAL",
            "impact": "Operator tidak tahu tekanan sudah 3x melebihi setpoint — risiko ledakan",
        },
        {
            "tag": "PAHH-101", "real_value": "ACTIVE", "unit": "-",
            "spoofed_value": "NORMAL", "real_status": "SIS_TRIPPED",
            "spoofed_status": "NORMAL",
            "impact": "Operator tidak tahu Safety System sudah trip — tidak ada manual intervensi",
        },
        {
            "tag": "XV-303", "real_value": "CLOSED", "unit": "-",
            "spoofed_value": "OPEN", "real_status": "VALVE_STUCK_CLOSED",
            "spoofed_status": "NORMAL",
            "impact": "Operator mengira katup terbuka padahal fluida tidak mengalir",
        },
    ]

    async def execute(self, context: TechniqueContext, result: TechniqueResult) -> None:
        spoof_method = context.extra.get("spoof_method", "replay_attack")
        target_tags = context.extra.get("target_tags", [s["tag"] for s in self.SPOOF_SCENARIOS])
        duration_minutes = context.extra.get("duration_minutes", 60)

        method_info = self.SPOOF_METHODS.get(spoof_method, self.SPOOF_METHODS["replay_attack"])

        output_lines = [
            f"[T0856 — SPOOF REPORTING MESSAGE]",
            f"Method        : {spoof_method}",
            f"Target SCADA  : {context.target_host}",
            f"Tags Spoofed  : {len(target_tags)} tags",
            f"Duration      : {duration_minutes} menit ({method_info['duration']})",
            f"{'─' * 60}",
            f"[i] {method_info['description']}",
            f"",
        ]

        detected = self._simulate_detection(method_info["detection_risk"])
        active_scenarios = [s for s in self.SPOOF_SCENARIOS if s["tag"] in target_tags]

        output_lines.extend([
            f"[SPOOFING ACTIVE — Apa yang OPERATOR LIHAT vs KONDISI NYATA]",
            f"{'─' * 60}",
            f"{'TAG':<12} {'REAL VALUE':<18} {'HMI SHOWS':<18} {'REAL STATUS':<20} IMPACT",
            f"{'─' * 60}",
        ])

        for scenario in active_scenarios:
            line = (
                f"{scenario['tag']:<12} "
                f"{str(scenario['real_value']) + ' ' + scenario['unit']:<18} "
                f"{str(scenario['spoofed_value']) + ' ' + scenario['unit']:<18} "
                f"{scenario['real_status']:<20} "
                f"← {scenario['impact'][:50]}..."
            )
            output_lines.append(line)

        output_lines.extend([
            f"",
            f"[OPERATOR PERSPECTIVE]",
            f"  HMI menampilkan: SEMUA NORMAL — tidak ada alarm aktif",
            f"  Kenyataan      : {len(active_scenarios)} kondisi berbahaya tersembunyi",
            f"",
        ])

        if detected:
            result.status = ExecutionStatus.PARTIAL
            output_lines.extend([
                f"[DETECTION] Sistem integrity check mendeteksi ketidaksesuaian nilai:",
                f"  • Historian value vs real-time value mismatch terdeteksi",
                f"  • Alert: 'Communication anomaly on {target_tags[0] if target_tags else 'unknown'}'",
                f"  • Spoofing masih aktif untuk {len(active_scenarios) - 1} tag lainnya",
            ])
        else:
            result.status = ExecutionStatus.SUCCESS
            output_lines.extend([
                f"[SUCCESS] Spoofing aktif selama {duration_minutes} menit tanpa deteksi.",
                f"",
                f"[IMPACT ANALYSIS]",
                f"  • Operator tidak mendapat informasi real kondisi proses",
                f"  • Safety response manual tidak akan dilakukan",
                f"  • Sistem otomatis tidak akan trip (nilai yang terlihat 'normal')",
                f"  • Waktu untuk kondisi kritis tanpa intervensi: ~{self._random_int(15, 45)} menit",
            ])
            result.collected_data.update({
                "spoofed_tags": [s["tag"] for s in active_scenarios],
                "hidden_conditions": [s["real_status"] for s in active_scenarios],
                "operator_blind_minutes": duration_minutes,
                "spoof_method": spoof_method,
            })

        result.artifacts_created = [f"spoof_config_{context.target_host}_{spoof_method}.cfg"]
        result.next_step_hints = [
            "T0843 (Program Download) — modifikasi PLC saat operator buta",
            "T0813 (Denial of Control) — blokir operator dari mengendalikan proses",
        ]
        result.output = "\n".join(output_lines)

    def _simulate_detection(self, probability: float) -> bool:
        import random
        return random.random() < probability

    def _random_int(self, min_v: int, max_v: int) -> int:
        import random
        return random.randint(min_v, max_v)
