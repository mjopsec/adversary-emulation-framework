"""
T0869 — Standard Application Layer Protocol (ICS — Command & Control)

Simulasi penggunaan protokol OT yang legitimate sebagai saluran C2.
Adversari menyembunyikan komunikasi C2 di dalam traffic Modbus, DNP3,
atau OPC-UA yang terlihat normal di jaringan OT.

Teknik ini sangat efektif karena:
1. Traffic OT sering tidak diinspeksi secara dalam
2. Tidak ada enkripsi pada Modbus/DNP3 — tapi juga tidak ada anomaly detection
3. Engineer jaringan OT sering tidak aware dengan pola serangan ini
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
class StandardAppLayerOTTechnique(BaseTechnique):
    """
    Simulasi C2 tersembunyi dalam protokol OT yang legitimate.

    Teknik ini memungkinkan adversari untuk:
    - Mengirimkan perintah ke implant yang sudah terpasang di OT network
    - Menerima data exfiltrasi dari jaringan OT yang terisolasi
    - Berbaur dengan traffic operasional yang normal
    """

    technique_id = "T0869"
    name = "Standard Application Layer Protocol (OT)"
    description = (
        "Adversari menggunakan protokol OT/ICS standar (Modbus, DNP3, OPC-UA) "
        "sebagai saluran komunikasi C2, menyembunyikan traffic berbahaya "
        "di dalam komunikasi operasional yang normal."
    )
    supported_environments = [Environment.OT]
    risk_level = "high"
    is_destructive = False
    requires_elevated_privileges = False
    tactic = "command-and-control"

    OT_C2_CHANNELS = {
        "modbus_covert": {
            "base_protocol": "Modbus TCP",
            "port": 502,
            "detection_risk": 0.10,
            "bandwidth_bps": 50,        # Sangat terbatas
            "method": "Encode C2 commands dalam read/write coil/register requests",
            "covert_channel": "Gunakan register 40001-40010 yang jarang dibaca untuk menyimpan C2 data",
            "indicators": [
                "Read/write ke register yang tidak pernah diakses oleh SCADA",
                "Pola akses register yang tidak sesuai engineering design",
            ],
        },
        "dnp3_data_objects": {
            "base_protocol": "DNP3",
            "port": 20000,
            "detection_risk": 0.15,
            "bandwidth_bps": 100,
            "method": "Encode data dalam DNP3 analog input object yang tidak dimonitor SCADA",
            "covert_channel": "Pakai DNP3 internal indication bits untuk sinyal C2",
            "indicators": [
                "DNP3 queries ke data object yang tidak ada dalam konfigurasi master",
                "Interval polling yang tidak sesuai standar operasional",
            ],
        },
        "opc_ua_nodes": {
            "base_protocol": "OPC-UA",
            "port": 4840,
            "detection_risk": 0.20,
            "bandwidth_bps": 1000,      # Lebih tinggi dari Modbus
            "method": "Gunakan custom OPC-UA node yang dibuat adversari untuk C2",
            "covert_channel": "Simpan C2 payload dalam custom node value yang terlihat seperti diagnostic data",
            "indicators": [
                "OPC-UA node yang tidak ada dalam address space yang dikonfigurasi",
                "Read/write ke node dari IP yang tidak terotorisasi",
            ],
        },
    }

    async def execute(self, context: TechniqueContext, result: TechniqueResult) -> None:
        ot_channel = context.extra.get("ot_channel", "modbus_covert")
        target_device = context.target_ip or context.target_host
        c2_payload_type = context.extra.get("payload_type", "beacon")

        channel_info = self.OT_C2_CHANNELS.get(ot_channel, self.OT_C2_CHANNELS["modbus_covert"])

        output_lines = [
            f"[T0869 — STANDARD OT PROTOCOL AS C2 CHANNEL]",
            f"OT Protocol     : {channel_info['base_protocol']} (port {channel_info['port']})",
            f"Target Device   : {target_device}",
            f"C2 Method       : {channel_info['method']}",
            f"Bandwidth       : {channel_info['bandwidth_bps']} bps (terbatas tapi cukup untuk C2)",
            f"{'─' * 65}",
            f"",
            f"[COVERT CHANNEL SETUP]",
            f"  {channel_info['covert_channel']}",
            f"",
        ]

        detected = self._simulate_detection(channel_info["detection_risk"])

        # Simulasi traffic C2 yang dikirimkan
        c2_traffic = self._generate_c2_traffic_sample(ot_channel, target_device)
        output_lines.extend([
            f"[C2 TRAFFIC SAMPLE — TERLIHAT SEBAGAI TRAFFIC OT NORMAL]",
            *c2_traffic,
            f"",
        ])

        if detected:
            result.status = ExecutionStatus.PARTIAL
            trigger = channel_info["indicators"][0]
            output_lines.extend([
                f"[DETECTION] OT security monitoring mendeteksi anomali:",
                f"  Trigger: {trigger}",
                f"  Alert: 'Unusual {channel_info['base_protocol']} access pattern'",
                f"  C2 channel terganggu — beberapa command berhasil terkirim sebelum terdeteksi.",
            ])
            result.next_step_hints = [
                "Rotasi ke OT C2 channel yang berbeda (pindah protokol)",
                "Kurangi frekuensi beacon — blend in dengan polling interval normal",
            ]
        else:
            result.status = ExecutionStatus.SUCCESS
            beacon_sent = self._random_int(5, 20)
            commands_executed = self._random_int(2, 8)
            output_lines.extend([
                f"[SUCCESS] Covert OT C2 channel berhasil dibuat.",
                f"",
                f"[COMMUNICATION STATS]",
                f"  Beacon terkirim    : {beacon_sent}x tanpa alert",
                f"  Commands dieksekusi: {commands_executed}x",
                f"  Bandwidth used     : {beacon_sent * channel_info['bandwidth_bps']} bytes",
                f"  Detected           : TIDAK — terlihat sebagai traffic operasional normal",
                f"",
                f"[INTELLIGENCE]",
                f"  OT network {target_device} sekarang dapat dikomunikasikan dari IT network",
                f"  Air gap antara IT dan OT TERJEMBATANI via {channel_info['base_protocol']}",
                f"  Potential data exfiltration dari OT network ke C2 eksternal",
            ])
            result.collected_data.update({
                "ot_channel": ot_channel,
                "protocol": channel_info["base_protocol"],
                "air_gap_bridged": True,
                "beacon_count": beacon_sent,
                "commands_executed": commands_executed,
            })
            result.artifacts_created = [f"ot_c2_config_{target_device}_{ot_channel}.cfg"]
            result.next_step_hints = [
                "T0843 (Program Download) — kirim modifikasi PLC via C2 channel ini",
                "T0856 (Spoof Reporting) — kirim instruksi spoof via OT C2",
                "T0802 (Automated Collection) — mulai kumpulkan data proses via channel ini",
            ]

        result.output = "\n".join(output_lines)

    def _generate_c2_traffic_sample(self, channel: str, target: str) -> list[str]:
        if channel == "modbus_covert":
            return [
                f"  Frame 1: Modbus Read Holding Register FC=03, Unit=1, Addr=40001, Count=10",
                f"  Frame 2: Modbus Write Single Register FC=06, Unit=1, Addr=40005, Value=0x4A43 [C2 beacon]",
                f"  Frame 3: Modbus Read Holding Register FC=03, Unit=1, Addr=40006, Count=4 [read response]",
                f"  ↑ Traffic ini terlihat identik dengan SCADA polling normal",
            ]
        elif channel == "dnp3_data_objects":
            return [
                f"  DNP3 Request: CONFIRM, seq=0x01, AI Group30 Var1 (analog input static)",
                f"  DNP3 Response: AI Index 255 Value=0x436F6D6D [encoded C2 command]",
                f"  DNP3 Request: WRITE Group80 Var1 Index=7 (internal indication) [ACK]",
                f"  ↑ DNP3 internal indication digunakan sebagai C2 handshake",
            ]
        else:
            return [
                f"  OPC-UA Read: NodeId=ns=2;s=Diagnostic.C2.Beacon Value='b64:SGVsbG8='",
                f"  OPC-UA Write: NodeId=ns=2;s=Diagnostic.C2.Response Value='b64:QUNLX09L'",
                f"  ↑ Node 'Diagnostic' terlihat legitimate — hidden di antara ribuan node OPC",
            ]

    def _simulate_detection(self, probability: float) -> bool:
        import random
        return random.random() < probability

    def _random_int(self, min_v: int, max_v: int) -> int:
        import random
        return random.randint(min_v, max_v)
