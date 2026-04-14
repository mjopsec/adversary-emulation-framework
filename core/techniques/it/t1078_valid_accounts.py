"""
T1078 — Valid Accounts (Persistence / Defense Evasion / Initial Access)

Simulasi penyalahgunaan akun yang valid untuk akses tidak sah.
Teknik ini sangat efektif karena menggunakan kredensial asli,
sehingga jauh lebih sulit dideteksi dibanding teknik eksploitasi.

Skenario yang disimulasikan:
- Default account abuse (admin bawaan yang belum diganti passwordnya)
- Domain account abuse (credential yang sudah di-harvest)
- Cloud account abuse (Azure AD, AWS IAM)
- Service account abuse (akun servis dengan privilege berlebih)
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
class ValidAccountsTechnique(BaseTechnique):
    """
    Simulasi penyalahgunaan akun valid untuk akses dan persistence.

    Teknik ini sering digunakan:
    - Setelah credential harvesting (T1003)
    - Sebagai persistent backdoor via service account
    - Untuk initial access dengan credential yang dileak/dibeli
    """

    technique_id = "T1078"
    name = "Valid Accounts"
    description = (
        "Adversari mendapatkan dan menggunakan kredensial akun yang valid "
        "untuk mendapatkan initial access, persistence, privilege escalation, "
        "atau defense evasion. Teknik ini sangat sulit dideteksi."
    )
    supported_environments = [Environment.IT]
    risk_level = "high"
    is_destructive = False
    requires_elevated_privileges = False
    tactic = "persistence"

    ACCOUNT_TYPES = {
        "local_admin": {
            "risk": "high",
            "stealth": "medium",
            "description": "Akun local administrator default (Administrator, admin, root)",
            "common_creds": [("administrator", "P@ssw0rd"), ("admin", "admin123"), ("root", "root")],
        },
        "domain_user": {
            "risk": "medium",
            "stealth": "high",
            "description": "Akun domain user yang credential-nya sudah di-harvest",
            "common_creds": [],  # Dari hasil T1003
        },
        "service_account": {
            "risk": "high",
            "stealth": "high",
            "description": "Service account dengan privilege berlebih (SQL service, IIS AppPool)",
            "common_creds": [("svc_sql", "SqlService2023!"), ("svc_iis", "Iis@Service1")],
        },
        "cloud_account": {
            "risk": "critical",
            "stealth": "medium",
            "description": "Cloud IAM account (Azure AD, AWS IAM) dengan excessive permissions",
            "common_creds": [],  # Token/key dari environment variables
        },
    }

    async def execute(self, context: TechniqueContext, result: TechniqueResult) -> None:
        account_type = context.extra.get("account_type", "local_admin")
        username = context.username or context.extra.get("username", "administrator")
        credential_source = context.extra.get("credential_source", "harvested")

        account_info = self.ACCOUNT_TYPES.get(account_type, self.ACCOUNT_TYPES["local_admin"])

        output_lines = [
            f"[T1078 — VALID ACCOUNTS]",
            f"Account Type       : {account_type}",
            f"Username           : {username}",
            f"Target             : {context.target_host}",
            f"Credential Source  : {credential_source}",
            f"{'─' * 55}",
        ]

        # Cek apakah ada credential
        if not context.password and not context.hash_value and not context.token:
            # Coba common default credentials
            result.status = ExecutionStatus.FAILED
            result.error = (
                "Tidak ada kredensial yang tersedia. "
                "Jalankan T1003 (Credential Dumping) atau T1110 (Brute Force) terlebih dahulu."
            )
            result.output = "\n".join(output_lines) + f"\n{result.error}"
            result.next_step_hints = ["T1110 (Brute Force)", "T1003 (Credential Dumping)"]
            return

        # Simulasi authentication attempt
        auth_method = "NTLM" if context.hash_value else "Password"
        output_lines.append(f"Auth Method        : {auth_method}")

        # Deteksi: lockout policy, anomaly detection, MFA
        detection_probability = self._calculate_detection(account_type, credential_source, context)
        detected = self._simulate_detection(detection_probability)

        if detected:
            result.status = ExecutionStatus.PARTIAL
            trigger = self._pick_detection_trigger(account_type)
            output_lines.append(
                f"\n[DETECTION] {trigger}\n"
                f"Alert: Suspicious login dari lokasi/waktu tidak biasa. "
                f"SIEM rule triggered: 'Anomalous Account Login Activity'."
            )
            result.next_step_hints = [
                "Tunggu beberapa jam sebelum retry (hindari lockout)",
                "Gunakan T1036 (Masquerading) untuk menyamarkan login",
                "Coba akun service yang login-nya tidak dimonitor secara ketat",
            ]
        else:
            result.status = ExecutionStatus.SUCCESS
            session_id = self._random_session_id()
            output_lines.extend([
                f"\n[SUCCESS] Autentikasi berhasil sebagai {username}@{context.target_host}",
                f"Session ID : {session_id}",
                f"Privilege  : {'SYSTEM/Admin' if account_type in ('local_admin', 'service_account') else 'User'}",
                f"MFA        : {'BYPASS — akun service tidak menggunakan MFA' if account_type == 'service_account' else 'N/A'}",
            ])
            result.collected_data.update({
                "authenticated_user": username,
                "session_id": session_id,
                "privilege_level": "admin" if account_type in ("local_admin", "service_account") else "user",
                "account_type": account_type,
            })
            result.artifacts_created = [f"auth_log_{context.target_host}_{username}.log"]
            result.next_step_hints = [
                "T1082 (System Discovery) — enumerasi sistem dengan akses ini",
                "T1021 (Remote Services) — gunakan akun ini untuk lateral movement",
                "T1003 (Credential Dumping) — dump lebih banyak kredensial",
            ]

        result.output = "\n".join(output_lines)

    def _calculate_detection(
        self, account_type: str, credential_source: str, context: TechniqueContext
    ) -> float:
        base = {
            "local_admin":    0.30,
            "domain_user":    0.20,
            "service_account": 0.15,
            "cloud_account":  0.35,
        }.get(account_type, 0.25)

        # Kredensial dari breach dump lebih sering flagged
        if credential_source == "breach_dump":
            base += 0.20

        return min(base, 0.90)

    def _pick_detection_trigger(self, account_type: str) -> str:
        import random
        triggers = {
            "local_admin":    ["Account Lockout Policy triggered after 5 failed attempts", "Unusual admin login outside business hours"],
            "domain_user":    ["User agent anomaly detected (new device)", "Impossible travel: login from 2 locations in 1 hour"],
            "service_account": ["Service account logged in interactively (unusual)", "Service account used for network login"],
            "cloud_account":  ["MFA prompt triggered", "Risky sign-in detected by Azure AD Identity Protection"],
        }
        options = triggers.get(account_type, ["Suspicious login detected"])
        return random.choice(options)

    def _simulate_detection(self, probability: float) -> bool:
        import random
        return random.random() < probability

    def _random_session_id(self) -> str:
        import random, string
        return "".join(random.choices(string.hexdigits.upper(), k=16))
