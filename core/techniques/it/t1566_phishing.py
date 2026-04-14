"""
T1566 — Phishing (Initial Access)

Simulasi pengiriman email phishing dan landing page palsu.
Teknik ini digunakan hampir semua kelompok APT sebagai metode initial access.

Sub-teknik yang dicakup:
- T1566.001 — Spearphishing Attachment
- T1566.002 — Spearphishing Link
- T1566.003 — Spearphishing via Service
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
class PhishingTechnique(BaseTechnique):
    """
    Simulasi kampanye phishing untuk initial access.

    Dalam mode simulasi (Phase 2), teknik ini mensimulasikan:
    1. Pembuatan email phishing dengan payload
    2. Pengiriman ke target
    3. Tracking apakah email dibuka dan payload dieksekusi

    Dalam mode eksekusi nyata (Phase 4+), teknik ini dapat:
    - Generate email phishing yang realistis
    - Buat landing page clone
    - Track click/open melalui GoPhish atau platform serupa
    """

    technique_id = "T1566"
    name = "Phishing"
    description = (
        "Adversari mengirimkan pesan phishing yang mengandung payload berbahaya "
        "atau link ke website yang dikontrol adversari untuk mendapatkan initial access."
    )
    supported_environments = [Environment.IT]
    risk_level = "medium"
    is_destructive = False
    requires_elevated_privileges = False
    tactic = "initial-access"

    # Variant yang tersedia
    VARIANTS = {
        "spearphishing_attachment": "Email dengan attachment berbahaya (macro, LNK, ISO)",
        "spearphishing_link":       "Email dengan link ke website clone atau payload dropper",
        "spearphishing_service":    "Phishing via LinkedIn, Slack, Teams, atau platform lain",
    }

    # Template subjek email yang realistis (untuk simulasi)
    REALISTIC_SUBJECTS = [
        "Urgent: Review required for Q4 Security Audit",
        "Action Required: Update your VPN credentials before Friday",
        "Invoice #{random} from {vendor} — Please review",
        "IT Department: Mandatory password reset notification",
        "Your account will be suspended — verify now",
        "Meeting invitation: Board Review — Confidential",
    ]

    async def execute(self, context: TechniqueContext, result: TechniqueResult) -> None:
        variant = context.extra.get("variant", "spearphishing_attachment")
        target_email = context.extra.get("target_email", f"user@{context.target_host}")
        sender_domain = context.extra.get("sender_domain", "trusted-vendor.com")

        result.output = self._simulate_phishing(variant, target_email, sender_domain, context)

        # Phishing kadang terdeteksi oleh email gateway
        # Simulasi berdasarkan variant: link lebih sering lolos dari attachment
        detection_chance = {"spearphishing_attachment": 0.35, "spearphishing_link": 0.20, "spearphishing_service": 0.10}
        detected = self._simulate_detection(detection_chance.get(variant, 0.25))

        if detected:
            result.status = ExecutionStatus.PARTIAL
            result.output += (
                "\n\n[DETECTION] Email gateway men-trigger rule suspicious attachment/URL. "
                "Email dikarantina sebelum mencapai inbox target. "
                "Pertimbangkan: encode payload, gunakan domain dengan reputasi tinggi, atau ganti ke spearphishing via service."
            )
            result.next_step_hints = [
                "Ganti ke T1566.003 (phishing via LinkedIn/Teams) yang bypass email gateway",
                "Coba T1190 (Exploit Public-Facing Application) sebagai alternative initial access",
            ]
        else:
            result.status = ExecutionStatus.SUCCESS
            result.collected_data["initial_access_method"] = variant
            result.collected_data["target_email"] = target_email
            result.collected_data["payload_delivered"] = True
            result.artifacts_created = [
                f"phishing_email_{target_email}.log",
                f"payload_delivery_{context.target_host}.log",
            ]
            result.next_step_hints = [
                "Lanjut ke T1059 (Command and Scripting Interpreter) untuk eksekusi payload",
                "Gunakan T1547 untuk persistence setelah payload dieksekusi",
            ]

    def _simulate_phishing(
        self, variant: str, target_email: str, sender_domain: str, context: TechniqueContext
    ) -> str:
        variant_descriptions = {
            "spearphishing_attachment": (
                f"Mengirimkan email ke {target_email} dari spoofed address noreply@{sender_domain}\n"
                f"Subject: 'Q4 Security Compliance — Action Required'\n"
                f"Attachment: Compliance_Report_Q4.docm (Word macro, 245 KB)\n"
                f"Payload: Macro downloads stager dari http://[redacted]/update.png"
            ),
            "spearphishing_link": (
                f"Mengirimkan email ke {target_email} dengan URL redirect\n"
                f"Subject: 'Mandatory VPN Credential Update'\n"
                f"Link: https://vpn-update.{sender_domain}/reset (clone portal VPN)\n"
                f"Tujuan: Harvest credentials via fake login page"
            ),
            "spearphishing_service": (
                f"Mengirimkan pesan via LinkedIn ke target {context.target_host}\n"
                f"Persona: HR Recruiter dari perusahaan terpercaya\n"
                f"Payload: 'Job Description.pdf.lnk' melalui SharePoint link\n"
                f"Keuntungan: Bypass email gateway, lebih dipercaya target"
            ),
        }
        return (
            f"[T1566 — PHISHING SIMULATION]\n"
            f"Variant: {variant}\n"
            f"{'─' * 50}\n"
            f"{variant_descriptions.get(variant, 'Unknown variant')}"
        )

    def _simulate_detection(self, probability: float) -> bool:
        import random
        return random.random() < probability
