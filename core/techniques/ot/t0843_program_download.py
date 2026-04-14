"""
T0843 — Program Download (ICS/OT — Execution / Impair Process Control)

Simulasi upload/download program berbahaya ke PLC atau RTU.
Ini adalah salah satu teknik paling berbahaya dalam ICS ATT&CK —
dapat mengubah logika kontrol proses secara fundamental.

Contoh nyata: Stuxnet menggunakan teknik ini untuk memodifikasi
program Siemens S7 PLC yang mengontrol sentrifugal nuklir Iran.

PERINGATAN PRODUKSI:
Teknik ini dikategorikan DESTRUCTIVE dalam lingkungan OT nyata.
Dalam Platform ini:
- DEFAULT: Simulasi penuh tanpa koneksi nyata ke PLC
- DENGAN IZIN EKSPLISIT: Koneksi ke PLC test/lab (bukan produksi)
- HARUS ADA PENGAWASAN LANGSUNG operator sistem
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
class ProgramDownloadTechnique(BaseTechnique):
    """
    Simulasi modifikasi program PLC/RTU yang tidak sah.

    Teknik ini mensimulasikan:
    1. Koneksi ke PLC via programming software (e.g., Step 7, RSLogix)
    2. Download program PLC saat ini untuk analisis
    3. Modifikasi logika ladder/function block
    4. Upload program yang dimodifikasi kembali ke PLC

    SAFETY GATE: Jika production_safe_mode=True, teknik ini
    akan SELALU diblokir oleh framework, bukan hanya disimulasikan.
    """

    technique_id = "T0843"
    name = "Program Download"
    description = (
        "Adversari memodifikasi program PLC/RTU untuk mengubah perilaku "
        "proses industri. Dapat digunakan untuk menyebabkan kondisi unsafe, "
        "menyembunyikan serangan, atau mempersiapkan payload destruktif."
    )
    supported_environments = [Environment.OT]
    risk_level = "critical"
    is_destructive = True          # SAFETY GATE: diblokir di production_safe_mode
    requires_elevated_privileges = False  # Banyak PLC tidak punya autentikasi
    tactic = "execution"

    # Vendor PLC yang disimulasikan
    PLC_VENDORS = {
        "siemens_s7": {
            "protocol": "S7comm (port 102)",
            "tool": "Step 7 / TIA Portal",
            "detection_risk": 0.40,
            "modification_types": ["Ladder Logic", "Function Block Diagram", "STL"],
        },
        "rockwell_ab": {
            "protocol": "EtherNet/IP (port 44818)",
            "tool": "RSLogix 5000 / Studio 5000",
            "detection_risk": 0.35,
            "modification_types": ["Ladder Logic", "Function Block"],
        },
        "schneider": {
            "protocol": "Modbus/TCP + proprietary (port 502)",
            "tool": "EcoStruxure Control Expert",
            "detection_risk": 0.30,
            "modification_types": ["Ladder Logic", "IL", "FBD"],
        },
        "generic_modbus": {
            "protocol": "Modbus TCP (port 502)",
            "tool": "Generic Modbus client",
            "detection_risk": 0.20,
            "modification_types": ["Register write"],
        },
    }

    # Tipe modifikasi yang disimulasikan
    MODIFICATION_SCENARIOS = {
        "setpoint_change": {
            "description": "Ubah setpoint sensor (suhu, tekanan, flow) di luar batas aman",
            "example": "Naikkan setpoint suhu dari 150°C ke 300°C — memicu overheat",
            "physical_impact": "Overheating → equipment damage atau kebakaran",
            "reversible": True,
        },
        "safety_bypass": {
            "description": "Bypass interlock dan safety system dalam logika PLC",
            "example": "Disable emergency shutdown trigger jika tekanan > threshold",
            "physical_impact": "Proses bisa beroperasi melebihi batas aman tanpa automatic shutdown",
            "reversible": True,
        },
        "valve_control": {
            "description": "Modifikasi logika pembukaan/penutupan katup kritis",
            "example": "Paksa XV-303 selalu OPEN, XV-101 selalu CLOSED",
            "physical_impact": "Aliran fluida tidak terkontrol → tumpahan atau tekanan berlebih",
            "reversible": True,
        },
        "false_feedback": {
            "description": "Program PLC untuk mengirimkan nilai sensor palsu ke SCADA",
            "example": "Laporan suhu 145°C padahal aktual 280°C",
            "physical_impact": "Operator tidak tahu kondisi bahaya yang sebenarnya",
            "reversible": True,
        },
    }

    async def execute(self, context: TechniqueContext, result: TechniqueResult) -> None:
        # NOTE: Safety gate di BaseTechnique.run() sudah handle production_safe_mode
        # Jika sampai sini, berarti sudah ada izin eksplisit

        plc_vendor = context.extra.get("plc_vendor", context.target_vendor or "generic_modbus")
        modification_type = context.extra.get("modification_type", "setpoint_change")
        download_only = context.extra.get("download_only", True)  # Default: hanya download, tidak upload

        vendor_info = self.PLC_VENDORS.get(plc_vendor, self.PLC_VENDORS["generic_modbus"])
        mod_scenario = self.MODIFICATION_SCENARIOS.get(modification_type, self.MODIFICATION_SCENARIOS["setpoint_change"])

        output_lines = [
            f"[T0843 — PROGRAM DOWNLOAD/UPLOAD]",
            f"PLC Vendor    : {plc_vendor.upper()}",
            f"Protocol      : {vendor_info['protocol']}",
            f"Tool          : {vendor_info['tool']}",
            f"Target PLC    : {context.target_host}",
            f"Mode          : {'DOWNLOAD ONLY (baca program)' if download_only else 'DOWNLOAD + MODIFY + UPLOAD'}",
            f"{'─' * 60}",
            f"",
            f"[STEP 1] Menghubungkan ke PLC...",
            f"  ✓ Koneksi {vendor_info['protocol']} berhasil",
            f"  ✓ PLC dalam mode RUN — switch ke PROG diperlukan untuk upload",
            f"",
            f"[STEP 2] Download program PLC saat ini...",
            f"  ✓ Program berhasil didownload ({self._random_int(45, 120)} KB)",
            f"  ✓ Decompile logic: {', '.join(vendor_info['modification_types'])}",
            f"",
        ]

        if download_only:
            output_lines.extend([
                f"[MODE: DOWNLOAD ONLY]",
                f"Program berhasil didownload untuk analisis.",
                f"Tidak ada modifikasi yang dilakukan ke PLC.",
                f"",
                f"[PROGRAM ANALYSIS]",
                f"  • Ditemukan {self._random_int(3, 8)} function block kritis",
                f"  • Emergency shutdown routine: BISA DIMODIFIKASI",
                f"  • Safety interlock: {self._random_int(2, 5)} bypass point ditemukan",
                f"  • Hardcoded setpoints yang bisa diubah: {self._random_int(10, 30)} parameter",
            ])
            result.status = ExecutionStatus.SUCCESS
            result.collected_data.update({
                "plc_vendor": plc_vendor,
                "program_downloaded": True,
                "bypass_points_found": self._random_int(2, 5),
                "modifiable_parameters": self._random_int(10, 30),
                "modification_type_planned": modification_type,
            })
            result.next_step_hints = [
                f"Re-run dengan download_only=False untuk upload program yang dimodifikasi",
                "T0856 (Spoof Reporting) untuk sembunyikan modifikasi dari operator",
            ]
        else:
            # Upload dengan modifikasi
            detected = self._simulate_detection(vendor_info["detection_risk"])

            output_lines.extend([
                f"[STEP 3] Memodifikasi program...",
                f"  Skenario    : {modification_type}",
                f"  Deskripsi   : {mod_scenario['description']}",
                f"  Contoh      : {mod_scenario['example']}",
                f"",
            ])

            if detected:
                result.status = ExecutionStatus.PARTIAL
                output_lines.extend([
                    f"[DETECTION] Sistem monitoring mendeteksi perubahan program PLC.",
                    f"  Alert: 'Unauthorized PLC program modification attempt'",
                    f"  Program upload dibatalkan — PLC dikembalikan ke mode RUN",
                    f"  Integrity check gagal — alarm ke operator.",
                ])
                result.next_step_hints = [
                    "Matikan log historian sebelum modifikasi berikutnya (T0815)",
                    "Gunakan legitimate engineering workstation yang sudah dikompromis",
                ]
            else:
                output_lines.extend([
                    f"[STEP 4] Upload program yang dimodifikasi...",
                    f"  ✓ PLC di-switch ke mode PROG",
                    f"  ✓ Program yang dimodifikasi berhasil diupload",
                    f"  ✓ PLC di-switch kembali ke mode RUN",
                    f"  ✓ Modifikasi aktif — proses berjalan dengan logika baru",
                    f"",
                    f"[PHYSICAL IMPACT SIMULATION]",
                    f"  Dampak yang diproyeksikan: {mod_scenario['physical_impact']}",
                    f"  Reversible: {'Ya — simpan backup program asli' if mod_scenario['reversible'] else 'TIDAK'}",
                    f"",
                    f"[!] PERINGATAN: Dalam engagement nyata, pastikan ada",
                    f"    operator sistem yang siap melakukan manual override.",
                ])
                result.status = ExecutionStatus.SUCCESS
                result.collected_data.update({
                    "plc_modified": True,
                    "modification_type": modification_type,
                    "physical_impact": mod_scenario["physical_impact"],
                    "backup_available": True,
                })
                result.artifacts_created = [
                    f"plc_program_original_{context.target_host}.bkp",
                    f"plc_program_modified_{context.target_host}.prg",
                ]

        result.output = "\n".join(output_lines)

    def _random_int(self, min_v: int, max_v: int) -> int:
        import random
        return random.randint(min_v, max_v)

    def _simulate_detection(self, probability: float) -> bool:
        import random
        return random.random() < probability
