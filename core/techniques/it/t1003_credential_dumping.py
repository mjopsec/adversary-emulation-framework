"""
T1003 — OS Credential Dumping (Credential Access)

Simulasi dumping kredensial dari berbagai sumber di sistem Windows dan Linux.
Hasil dari teknik ini (hash/password) digunakan untuk lateral movement dan
privilege escalation.

Sub-teknik yang disimulasikan:
- T1003.001 — LSASS Memory (Mimikatz-style)
- T1003.002 — Security Account Manager (SAM)
- T1003.003 — NTDS (Active Directory database)
- T1003.004 — LSA Secrets
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
class CredentialDumpingTechnique(BaseTechnique):
    """
    Simulasi OS credential dumping dari berbagai sumber.

    PENTING: Teknik ini memerlukan elevated privileges (SYSTEM atau Admin).
    Tanpa hak akses yang cukup, operasi akan gagal.

    Data yang dikumpulkan dalam simulasi:
    - NTLM hashes dari SAM database
    - Cleartext credentials dari LSA Secrets
    - Kerberos tickets dari LSASS
    - Domain hashes dari NTDS.dit (jika di Domain Controller)
    """

    technique_id = "T1003"
    name = "OS Credential Dumping"
    description = (
        "Adversari mendump kredensial dari OS dan software untuk menemukan "
        "password dan hashes yang bisa digunakan untuk akses lebih jauh."
    )
    supported_environments = [Environment.IT]
    risk_level = "high"
    is_destructive = False
    requires_elevated_privileges = True
    tactic = "credential-access"

    DUMP_METHODS = {
        "lsass_memory": {
            "requires": "SYSTEM privilege",
            "detection_risk": 0.65,  # Sangat high — semua EDR monitor LSASS
            "tools": ["Mimikatz sekurlsa::logonpasswords", "ProcDump + Mimikatz offline", "Comsvcs.dll MiniDump"],
            "yields": ["NTLM hashes", "Cleartext passwords (jika WDigest enabled)", "Kerberos tickets"],
        },
        "sam_registry": {
            "requires": "SYSTEM privilege",
            "detection_risk": 0.40,
            "tools": ["reg save HKLM\\SAM", "Impacket secretsdump.py", "CrackMapExec --sam"],
            "yields": ["Local account NTLM hashes"],
        },
        "ntds_dit": {
            "requires": "Domain Admin",
            "detection_risk": 0.50,
            "tools": ["DCSync (Mimikatz lsadump::dcsync)", "ntdsutil", "VSS Shadow Copy + secretsdump"],
            "yields": ["All domain account hashes", "Kerberoastable service hashes", "krbtgt hash (Golden Ticket)"],
        },
        "lsa_secrets": {
            "requires": "SYSTEM privilege",
            "detection_risk": 0.35,
            "tools": ["reg save HKLM\\SECURITY", "Impacket secretsdump.py", "secretsdump --lsa"],
            "yields": ["Service account cleartext passwords", "Machine account credentials", "VPN credentials"],
        },
    }

    # Kredensial yang akan "ditemukan" dalam simulasi
    SIMULATED_CREDENTIALS = [
        {"user": "jsmith",      "hash": "e52cac67419a9a224a3b108f3fa6cb6d", "type": "ntlm", "context": "Domain User"},
        {"user": "dbadmin",     "hash": "8846f7eaee8fb117ad06bdd830b7586c", "type": "ntlm", "context": "DB Admin (simulated)"},
        {"user": "svc_backup",  "cleartext": "Backup@2024!", "type": "cleartext", "context": "Backup Service Account"},
        {"user": "Administrator","hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", "type": "ntlm", "context": "Local Admin"},
    ]

    async def execute(self, context: TechniqueContext, result: TechniqueResult) -> None:
        dump_method = context.extra.get("dump_method", "sam_registry")
        check_privileges = context.extra.get("check_privileges", True)

        method_info = self.DUMP_METHODS.get(dump_method, self.DUMP_METHODS["sam_registry"])
        is_dc_target = context.extra.get("is_dc", False)

        output_lines = [
            f"[T1003 — OS CREDENTIAL DUMPING]",
            f"Method          : {dump_method}",
            f"Target          : {context.target_host}",
            f"Requires        : {method_info['requires']}",
            f"{'─' * 55}",
        ]

        # Privilege check
        privilege_ok = context.extra.get("has_admin", True)
        if check_privileges and not privilege_ok:
            result.status = ExecutionStatus.FAILED
            output_lines.append(
                f"\n[FAILED] Insufficient privileges. Diperlukan: {method_info['requires']}. "
                f"Jalankan privilege escalation (T1134, T1548) terlebih dahulu."
            )
            result.output = "\n".join(output_lines)
            result.next_step_hints = ["T1134 (Access Token Manipulation)", "T1548 (Abuse Elevation Control)"]
            return

        # Khusus NTDS.dit: hanya di Domain Controller
        if dump_method == "ntds_dit" and not is_dc_target:
            dump_method = "sam_registry"
            method_info = self.DUMP_METHODS["sam_registry"]
            output_lines.append(
                "[i] Target bukan Domain Controller — switching ke SAM dump."
            )

        output_lines.append(f"Tools used      : {', '.join(method_info['tools'][:2])}")

        detected = self._simulate_detection(method_info["detection_risk"])

        if detected:
            result.status = ExecutionStatus.PARTIAL
            output_lines.append(
                f"\n[DETECTION] EDR alert: 'Credential Access via {dump_method}'. "
                f"{'LSASS process access blocked by Credential Guard.' if dump_method == 'lsass_memory' else 'Registry key access flagged by AV.'}"
                f" Operasi berhasil sebagian — beberapa hash berhasil diambil sebelum diblokir."
            )
            # Partial success: berhasil dapat sebagian
            partial_creds = self.SIMULATED_CREDENTIALS[:1]
            self._add_credentials_to_result(partial_creds, result)
            result.next_step_hints = [
                "Coba T1003.004 (LSA Secrets) yang detection risk-nya lebih rendah",
                "Gunakan DCSync dari remote daripada langsung di target",
                "Disable Credential Guard sebelum retry (T1562)",
            ]
        else:
            result.status = ExecutionStatus.SUCCESS
            # Jumlah kredensial berdasarkan metode
            cred_count = {"lsass_memory": 4, "sam_registry": 2, "ntds_dit": 4, "lsa_secrets": 2}.get(dump_method, 2)
            harvested = self.SIMULATED_CREDENTIALS[:cred_count]

            output_lines.extend([
                f"\n[SUCCESS] Credential dump berhasil. {len(harvested)} credential ditemukan:",
                *[f"  [{c['type'].upper()}] {c['user']}: {c.get('hash', c.get('cleartext', '[hidden]'))[:20]}... ({c['context']})"
                  for c in harvested],
            ])

            if dump_method == "ntds_dit":
                output_lines.append(
                    "\n[!] krbtgt hash berhasil diambil — GOLDEN TICKET POSSIBLE!"
                )

            self._add_credentials_to_result(harvested, result)
            output_lines.append(f"\nData yang dapat dikumpulkan: {', '.join(method_info['yields'])}")
            result.artifacts_created = [f"creds_dump_{context.target_host}_{dump_method}.txt"]
            result.next_step_hints = [
                "T1078 (Valid Accounts) — gunakan hash untuk Pass-the-Hash",
                "T1021 (Remote Services) — lateral movement dengan kredensial baru",
                "T1558 (Steal Kerberos Ticket) — jika Kerberos tickets berhasil diambil",
            ]

        result.output = "\n".join(output_lines)

    def _add_credentials_to_result(self, creds: list[dict], result: TechniqueResult) -> None:
        result.collected_data.setdefault("credentials", [])
        result.collected_data["credentials"].extend(creds)

    def _simulate_detection(self, probability: float) -> bool:
        import random
        return random.random() < probability
