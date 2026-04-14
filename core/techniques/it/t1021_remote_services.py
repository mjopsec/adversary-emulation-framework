"""
T1021 — Remote Services (Lateral Movement)

Simulasi lateral movement menggunakan protokol remote services yang legitimate.
Teknik ini digunakan setelah mendapatkan kredensial valid untuk berpindah
dari satu sistem ke sistem lainnya dalam jaringan.

Sub-teknik yang disimulasikan:
- T1021.001 — Remote Desktop Protocol (RDP)
- T1021.002 — SMB/Windows Admin Shares
- T1021.004 — SSH
- T1021.006 — Windows Remote Management (WinRM)
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
class RemoteServicesTechnique(BaseTechnique):
    """
    Simulasi lateral movement menggunakan remote services.

    Digunakan setelah mendapatkan:
    - Kredensial valid (dari T1003, T1078)
    - NTLM hash (untuk Pass-the-Hash)
    - Kerberos ticket (untuk Pass-the-Ticket)
    """

    technique_id = "T1021"
    name = "Remote Services"
    description = (
        "Adversari menggunakan protokol remote services yang valid (RDP, SMB, SSH, WinRM) "
        "untuk lateral movement antar sistem menggunakan kredensial yang sudah di-harvest."
    )
    supported_environments = [Environment.IT]
    risk_level = "high"
    is_destructive = False
    requires_elevated_privileges = False
    tactic = "lateral-movement"

    PROTOCOLS = {
        "rdp": {
            "port": 3389,
            "detection_risk": 0.40,
            "noise_level": "high",    # RDP login sangat terlihat di log
            "description": "Remote Desktop Protocol — interactive graphical session",
            "blocked_by": ["Network segmentation", "RDP gateway", "Just-in-time access"],
        },
        "smb": {
            "port": 445,
            "detection_risk": 0.30,
            "noise_level": "medium",
            "description": "SMB Admin Shares (C$, ADMIN$, IPC$)",
            "blocked_by": ["Host-based firewall", "SMB signing enforcement"],
        },
        "ssh": {
            "port": 22,
            "detection_risk": 0.20,
            "noise_level": "low",
            "description": "SSH untuk target Linux/Unix dengan key atau password",
            "blocked_by": ["SSH key-only auth", "Network ACL"],
        },
        "winrm": {
            "port": 5985,
            "detection_risk": 0.25,
            "noise_level": "medium",
            "description": "Windows Remote Management (HTTP/HTTPS) — PowerShell remoting",
            "blocked_by": ["WinRM disabled by default", "PowerShell Constrained Language Mode"],
        },
        "wmi": {
            "port": 135,
            "detection_risk": 0.20,
            "noise_level": "low",     # WMI traffic sering dianggap normal
            "description": "WMI — remote execution tanpa file transfer",
            "blocked_by": ["DCOM restrictions", "Windows Firewall"],
        },
    }

    async def execute(self, context: TechniqueContext, result: TechniqueResult) -> None:
        protocol = context.extra.get("protocol", "smb")
        auth_method = context.extra.get("auth_method", "password")  # password | pth | ptt | key
        lateral_target = context.extra.get("lateral_target", context.target_host)

        if not (context.username and (context.password or context.hash_value)):
            result.status = ExecutionStatus.FAILED
            result.error = (
                "Tidak ada kredensial untuk lateral movement. "
                "Pastikan sudah menjalankan T1003 atau T1078 sebelumnya."
            )
            result.output = result.error
            return

        proto_info = self.PROTOCOLS.get(protocol, self.PROTOCOLS["smb"])
        detection_risk = proto_info["detection_risk"]

        # Pass-the-Hash lebih sulit dideteksi dari password auth jika dikonfigurasi benar
        if auth_method == "pth":
            detection_risk *= 0.80

        output_lines = [
            f"[T1021 — REMOTE SERVICES — LATERAL MOVEMENT]",
            f"Protocol    : {protocol.upper()} (port {proto_info['port']})",
            f"Auth Method : {auth_method.upper()}",
            f"Source      : {context.target_host}",
            f"Target      : {lateral_target}",
            f"Credential  : {context.username}:{context.hash_value[:8] + '...' if context.hash_value else '[password]'}",
            f"{'─' * 55}",
            f"[i] {proto_info['description']}",
        ]

        # Cek konektivitas ke target (simulasi)
        port_open = self._simulate_port_check(proto_info["port"])
        if not port_open:
            result.status = ExecutionStatus.FAILED
            output_lines.append(
                f"\n[BLOCKED] Port {proto_info['port']}/{protocol.upper()} ditutup atau difilter. "
                f"Diblokir oleh: {', '.join(proto_info['blocked_by'][:2])}"
            )
            result.output = "\n".join(output_lines)
            result.next_step_hints = [
                f"Coba protokol alternatif: {self._suggest_alternative(protocol)}",
                "Evaluasi jalur jaringan yang berbeda ke target",
            ]
            return

        detected = self._simulate_detection(detection_risk)

        if detected:
            result.status = ExecutionStatus.PARTIAL
            output_lines.append(
                f"\n[DETECTION] NDR/SIEM alert: 'Lateral Movement via {protocol.upper()}'. "
                f"Log entry: {context.username} logged in from {context.target_host} to {lateral_target}. "
                f"Alert severity: HIGH."
            )
            result.next_step_hints = [
                f"Gunakan protokol dengan noise lebih rendah (WMI, WinRM via HTTPS)",
                "Tunggu jam operasional normal untuk blend in dengan traffic legitimate",
                "Gunakan T1550 (Use Alternate Authentication Material) — Pass-the-Ticket",
            ]
        else:
            result.status = ExecutionStatus.SUCCESS
            share_mounted = protocol == "smb"
            output_lines.extend([
                f"\n[SUCCESS] Koneksi ke {lateral_target} via {protocol.upper()} berhasil.",
                f"Session sebagai: {context.username}",
                f"Share mounted : {'C$ ADMIN$ berhasil di-mount' if share_mounted else 'N/A'}",
                f"Remote shell  : {'TERSEDIA' if protocol in ('winrm', 'ssh', 'wmi') else 'Via file drop'}",
            ])
            result.collected_data.update({
                "lateral_target": lateral_target,
                "protocol_used": protocol,
                "auth_method": auth_method,
                "remote_session": True,
                "share_access": share_mounted,
            })
            result.artifacts_created = [
                f"lateral_session_{lateral_target}_{protocol}.log",
                f"\\\\{lateral_target}\\ADMIN$" if share_mounted else "",
            ]
            result.next_step_hints = [
                f"T1059 (Command Scripting) di target {lateral_target}",
                "T1003 (Credential Dumping) di target baru untuk pivot lebih jauh",
                "T1082 (System Discovery) — petakan sistem baru",
            ]

        result.output = "\n".join(output_lines)

    def _simulate_port_check(self, port: int) -> bool:
        import random
        # 80% chance port terbuka (kecuali RDP yang sering diblokir)
        open_probability = 0.70 if port == 3389 else 0.82
        return random.random() < open_probability

    def _simulate_detection(self, probability: float) -> bool:
        import random
        return random.random() < probability

    def _suggest_alternative(self, failed_protocol: str) -> str:
        alternatives = {
            "rdp":   "WinRM atau SMB",
            "smb":   "WMI atau WinRM",
            "ssh":   "Telnet atau RDP (jika tersedia)",
            "winrm": "WMI atau SMB",
            "wmi":   "WinRM atau SMB",
        }
        return alternatives.get(failed_protocol, "protokol lain yang tersedia")
