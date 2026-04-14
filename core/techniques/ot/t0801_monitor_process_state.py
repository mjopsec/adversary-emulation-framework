"""
T0801 — Monitor Process State (ICS/OT — Collection)

Simulasi pemantauan kondisi proses industri secara tidak sah
dengan membaca nilai sensor, register PLC, dan status peralatan.

Dalam lingkungan ICS, teknik ini digunakan untuk:
- Reconnaissance sebelum serangan sabotase
- Mencuri data proses industri bernilai tinggi
- Memahami "normal state" sebelum memanipulasi nilai

Protokol yang disimulasikan: Modbus TCP, DNP3, OPC-UA
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
class MonitorProcessStateTechnique(BaseTechnique):
    """
    Simulasi pembacaan status proses industri via protokol OT.

    Mode default: READ-ONLY — tidak ada modifikasi ke proses.
    Teknik ini aman untuk lingkungan produksi (jika read-only).
    """

    technique_id = "T0801"
    name = "Monitor Process State"
    description = (
        "Adversari mengumpulkan informasi tentang status proses fisik "
        "dengan mengakses data dari controller dan field devices. "
        "Data ini digunakan untuk perencanaan serangan selanjutnya."
    )
    supported_environments = [Environment.OT]
    risk_level = "low"       # Read-only — risiko rendah ke proses
    is_destructive = False
    requires_elevated_privileges = False
    tactic = "collection"

    # Nilai sensor yang disimulasikan (mewakili proses industri yang umum)
    SIMULATED_PROCESS_DATA = {
        "temperature_sensors": [
            {"tag": "TIC-101", "value": 145.3, "unit": "°C", "setpoint": 150.0, "status": "NORMAL"},
            {"tag": "TIC-202", "value": 89.7,  "unit": "°C", "setpoint": 90.0,  "status": "NORMAL"},
            {"tag": "TIC-303", "value": 210.1, "unit": "°C", "setpoint": 200.0, "status": "HIGH_ALARM"},
        ],
        "pressure_sensors": [
            {"tag": "PIC-101", "value": 6.2,  "unit": "bar", "setpoint": 6.0, "status": "NORMAL"},
            {"tag": "PIC-202", "value": 12.8, "unit": "bar", "setpoint": 10.0, "status": "HIGH_ALARM"},
        ],
        "flow_sensors": [
            {"tag": "FIC-101", "value": 125.4, "unit": "L/min", "setpoint": 120.0, "status": "NORMAL"},
            {"tag": "FIC-202", "value": 0.0,   "unit": "L/min", "setpoint": 80.0,  "status": "NO_FLOW"},
        ],
        "valve_positions": [
            {"tag": "XV-101", "position": "OPEN",    "commanded": "OPEN",   "status": "NORMAL"},
            {"tag": "XV-202", "position": "CLOSED",  "commanded": "CLOSED", "status": "NORMAL"},
            {"tag": "XV-303", "position": "PARTIAL", "commanded": "OPEN",   "status": "FAULT"},
        ],
        "pump_status": [
            {"tag": "PUMP-A", "running": True,  "speed_rpm": 1450, "current_amp": 23.5, "status": "RUNNING"},
            {"tag": "PUMP-B", "running": False, "speed_rpm": 0,    "current_amp": 0.0,  "status": "STANDBY"},
        ],
        "safety_systems": [
            {"tag": "PAHH-101", "status": "BYPASSED", "alarm": True,  "note": "KRITIS: SIS bypass aktif!"},
            {"tag": "PSLL-202", "status": "ACTIVE",   "alarm": False, "note": "Normal"},
        ],
    }

    PROTOCOLS = {
        "modbus": {
            "port": 502,
            "detection_risk": 0.10,  # Modbus tidak ada autentikasi — query sulit dibedakan
            "description": "Modbus TCP — baca coil dan holding register dari PLC",
        },
        "dnp3": {
            "port": 20000,
            "detection_risk": 0.15,
            "description": "DNP3 — baca data object dari RTU/SCADA",
        },
        "opc_ua": {
            "port": 4840,
            "detection_risk": 0.20,  # OPC-UA ada logging, lebih terdeteksi
            "description": "OPC-UA — baca node value dari OPC server",
        },
    }

    async def execute(self, context: TechniqueContext, result: TechniqueResult) -> None:
        protocol = context.protocol or context.extra.get("protocol", "modbus")
        plc_address = context.target_ip or context.target_host

        proto_info = self.PROTOCOLS.get(protocol, self.PROTOCOLS["modbus"])

        output_lines = [
            f"[T0801 — MONITOR PROCESS STATE]",
            f"Protocol    : {protocol.upper()} (port {proto_info['port']})",
            f"PLC/RTU     : {plc_address}",
            f"Mode        : READ-ONLY (aman untuk produksi)",
            f"{'─' * 60}",
            f"[i] {proto_info['description']}",
            f"",
        ]

        detected = self._simulate_detection(proto_info["detection_risk"])

        # Dalam semua kasus (detected atau tidak), kita berhasil baca data
        # Modbus tidak ada autentikasi, jadi baca selalu berhasil
        output_lines.append("[PROCESS DATA COLLECTED]")
        output_lines.append("")

        all_findings = []

        for category, items in self.SIMULATED_PROCESS_DATA.items():
            output_lines.append(f"  ▶ {category.replace('_', ' ').upper()}")
            for item in items:
                status = item.get("status", "UNKNOWN")
                alarm_marker = " ⚠" if "ALARM" in status or "FAULT" in status or "BYPASS" in status or "NO_FLOW" in status else ""
                if "value" in item:
                    line = f"    {item['tag']}: {item['value']} {item.get('unit', '')} | SP: {item.get('setpoint', 'N/A')} | [{status}]{alarm_marker}"
                elif "position" in item:
                    line = f"    {item['tag']}: {item['position']} (commanded: {item['commanded']}) | [{status}]{alarm_marker}"
                elif "running" in item:
                    line = f"    {item['tag']}: {'RUNNING' if item['running'] else 'STOPPED'} @ {item.get('speed_rpm', 0)} RPM | [{status}]{alarm_marker}"
                else:
                    line = f"    {item['tag']}: [{status}]{alarm_marker} — {item.get('note', '')}"
                output_lines.append(line)
                if alarm_marker:
                    all_findings.append(f"{item['tag']}: {status}")
            output_lines.append("")

        if all_findings:
            output_lines.extend([
                f"[!] ANOMALI DITEMUKAN ({len(all_findings)} item):",
                *[f"  • {f}" for f in all_findings],
                "",
                "[INTELLIGENCE] Data ini mengungkap:",
                "  • SIS bypass aktif (PAHH-101) — safety system dapat dimanipulasi",
                "  • Tekanan PIC-202 sudah melebihi setpoint — proses dalam kondisi abnormal",
                "  • Katup XV-303 FAULT — tanda ada masalah mekanis atau sinyal yang dimanipulasi",
            ])

        if detected:
            result.status = ExecutionStatus.PARTIAL
            output_lines.append(
                f"\n[DETECTION] Historian/OPC server mencatat akses query yang tidak biasa "
                f"dari {plc_address}. Log: 'Unauthorized read access from {context.target_host}'. "
                f"Data berhasil dikumpulkan sebelum terdeteksi."
            )
        else:
            result.status = ExecutionStatus.SUCCESS
            output_lines.append(
                f"\n[SUCCESS] Semua data proses berhasil dikumpulkan tanpa alert. "
                f"Modbus tidak memiliki autentikasi — query tidak tercatat di sebagian besar DCS."
            )

        result.collected_data.update({
            "process_snapshot": self.SIMULATED_PROCESS_DATA,
            "anomalies_found": all_findings,
            "sis_bypass_active": True,
            "unsafe_conditions": len(all_findings),
            "protocol_used": protocol,
        })
        result.artifacts_created = [f"process_snapshot_{plc_address}_{protocol}.json"]
        result.next_step_hints = [
            "T0843 (Program Download) — upload firmware berbahaya ke PLC yang sudah dipetakan",
            "T0856 (Spoof Reporting Message) — sembunyikan kondisi abnormal dari operator",
            "T0869 (Standard Application Layer Protocol) — gunakan protokol OT untuk C2",
        ]
        result.output = "\n".join(output_lines)

    def _simulate_detection(self, probability: float) -> bool:
        import random
        return random.random() < probability
