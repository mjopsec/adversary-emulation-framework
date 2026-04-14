"""
Task Dispatcher — Routing eksekusi teknik ke agent atau simulasi lokal.

Dispatcher memutuskan:
1. Apakah ada agent aktif di target? → Route ke agent (realistic execution)
2. Tidak ada agent? → Fallback ke direct simulation (Phase 1-3 behavior)

Routing logic:
  target_ip → find_agent_for_target() → agent found?
    YES: queue task ke agent, tunggu result (polling atau callback)
    NO:  jalankan langsung via TechniqueRegistry (simulasi)

Dispatcher juga mengatur context enrichment:
- Inject info dari agent (OS, privilege, installed software) ke TechniqueContext
- Update execution record dengan source (agent vs simulation)
"""

from __future__ import annotations

import asyncio
import json as _json
import time as _time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from core.agent.agent_manager import AgentManager
from core.models.agent import Agent
from core.techniques.base import ExecutionStatus, TechniqueContext, TechniqueResult
from core.techniques.registry import TechniqueRegistry


# ─── Shannon API Global Rate Limiter ─────────────────────────────────────────
# Singleton yang memastikan minimum interval antar panggilan Shannon.
# Mencegah burst requests yang memicu 429.

class _ShannonRateLimiter:
    """
    Serialisasi panggilan Shannon API dengan minimum spacing.

    Jika dua coroutine memanggil bersamaan, yang kedua akan menunggu
    sampai interval minimum terpenuhi setelah panggilan sebelumnya selesai.
    """
    # Minimum jeda antar panggilan (detik). Shannon tampak punya ~10 RPM limit.
    MIN_INTERVAL: float = 7.0

    def __init__(self) -> None:
        self._last_call: float = 0.0
        self._lock: asyncio.Lock | None = None

    def _get_lock(self) -> asyncio.Lock:
        # Lazy-init agar tidak perlu running event loop saat import
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def wait(self) -> None:
        """Tunggu sampai aman untuk memanggil Shannon lagi."""
        async with self._get_lock():
            now = _time.monotonic()
            elapsed = now - self._last_call
            if self._last_call > 0 and elapsed < self.MIN_INTERVAL:
                wait_s = self.MIN_INTERVAL - elapsed
                logger.debug("Shannon rate limiter: menunggu {:.1f}s sebelum request berikutnya", wait_s)
                await asyncio.sleep(wait_s)
            self._last_call = _time.monotonic()


_shannon_rl = _ShannonRateLimiter()

# Third-party Python packages that are NOT available on a default target.
# If a python_exec command imports any of these, downgrade to shell_command.
_THIRD_PARTY_PY_MODULES = {
    "netifaces", "impacket", "psutil", "requests", "httpx", "paramiko",
    "scapy", "nmap", "ldap3", "pywin32", "win32api", "win32con", "win32security",
    "wmi", "comtypes", "pycparser", "cryptography", "pyOpenSSL", "ldap",
    "netaddr", "dpapi", "bloodhound", "pwntools", "pyautogui", "PIL",
    "cv2", "numpy", "pandas", "yaml", "toml", "dotenv",
}

# Standard Python library modules that ARE safe to use
_STDLIB_SAFE = {
    "socket", "subprocess", "os", "sys", "ctypes", "winreg", "struct",
    "ipaddress", "platform", "shutil", "pathlib", "glob", "re", "json",
    "base64", "hashlib", "threading", "multiprocessing", "tempfile",
    "io", "time", "datetime", "collections", "itertools", "functools",
    "signal", "logging", "argparse", "string", "random", "secrets",
    "http", "urllib", "email", "ssl", "select", "queue", "atexit",
}


def _sanitize_python_command(plan: dict, os_type: str = "windows") -> dict:
    """
    Jika python_exec command menggunakan third-party modules yang tidak tersedia,
    downgrade ke shell_command yang setara menggunakan native OS binaries.
    """
    if plan.get("task_type") != "python_exec":
        return plan

    cmd = plan.get("command", "")
    # Ekstrak semua nama module yang di-import
    import re as _re
    imported = set(_re.findall(
        r"(?:^|\s|;)import\s+([\w,\s]+)|from\s+([\w.]+)\s+import",
        cmd, _re.MULTILINE
    ))
    # Flatten: kedua capture group
    imported_names: set[str] = set()
    for g1, g2 in imported:
        for name in (g1 + " " + g2).split(","):
            base = name.strip().split(".")[0]
            if base:
                imported_names.add(base)

    bad_modules = imported_names & _THIRD_PARTY_PY_MODULES
    if not bad_modules:
        return plan  # command is fine

    logger.warning(
        "python_exec command uses third-party modules {} — downgrading to shell_command",
        bad_modules,
    )

    # Replace with native OS equivalent
    is_win = os_type.lower() in ("windows", "win", "win32", "win64")
    if is_win:
        fallback_cmd = (
            "ipconfig /all && netstat -an && tasklist /fo csv && "
            "net user && net localgroup administrators && "
            "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        )
    else:
        fallback_cmd = (
            "ip addr; ip route; ss -tlnp; ps aux; id; whoami; "
            "cat /etc/passwd | grep -v nologin; ls /tmp"
        )

    return {
        **plan,
        "task_type": "shell_command",
        "command": fallback_cmd,
        "explanation": (
            plan.get("explanation", "") +
            f" [Note: original used {bad_modules} — replaced with native OS commands]"
        ),
    }


def _wrap_python_exec_as_shell(plan: dict, os_type: str = "windows") -> dict:
    """
    Konversi python_exec plan ke shell_command dengan wrapper 'python -c "..."'.

    Ini membuat command langsung bisa dijalankan di terminal tanpa setup apapun.
    Menangani escaping untuk:
    - Backslash (Windows paths): \\ → \\\\
    - Double quotes: " → \\"
    - Multi-line code: digabung dengan '; '
    """
    if plan.get("task_type") != "python_exec":
        return plan

    raw_code = plan.get("command", "").strip()
    if not raw_code:
        return plan

    # Gabungkan multi-line ke one-liner (skip comment-only lines)
    lines = []
    for line in raw_code.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            lines.append(stripped)
    code_oneliner = "; ".join(lines) if lines else raw_code.replace("\n", "; ")

    is_win = os_type.lower() in ("windows", "win", "win32", "win64")
    python_bin = "python" if is_win else "python3"

    # Escape untuk embedding dalam double-quoted string shell:
    # 1. Escape backslash dulu (sebelum escape karakter lain)
    # 2. Escape double-quote
    escaped = code_oneliner.replace("\\", "\\\\").replace('"', '\\"')

    cmd = f'{python_bin} -c "{escaped}"'

    return {
        **plan,
        "task_type": "shell_command",
        "command": cmd,
    }


@dataclass
class DispatchResult:
    """Hasil dispatch dari TaskDispatcher."""
    technique_id: str
    target: str
    status: ExecutionStatus
    output: str = ""
    error: str = ""
    artifacts: list[str] = None
    collected_data: dict = None
    duration_seconds: float | None = None
    dispatched_via: str = "simulation"   # "agent" | "simulation" | "registry"
    agent_id: str | None = None
    task_id: str | None = None

    def __post_init__(self) -> None:
        if self.artifacts is None:
            self.artifacts = []
        if self.collected_data is None:
            self.collected_data = {}

    @property
    def is_success(self) -> bool:
        return self.status == ExecutionStatus.SUCCESS

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "target": self.target,
            "status": self.status.value,
            "output": self.output,
            "error": self.error,
            "artifacts": self.artifacts,
            "collected_data": self.collected_data,
            "duration_seconds": self.duration_seconds,
            "dispatched_via": self.dispatched_via,
            "agent_id": self.agent_id,
            "task_id": self.task_id,
        }


class TaskDispatcher:
    """
    Dispatcher teknik ke agent (jika tersedia) atau simulasi lokal.

    Hierarki dispatch:
    1. Agent routing — jika ada agent aktif di target IP
    2. Registry execution — jika teknik ada implementasi konkretnya
    3. Probabilistic simulation — fallback terakhir
    """

    # Timeout menunggu agent menyelesaikan task (detik)
    # Harus > beacon_interval agent (default 60s) + eksekusi command + Shannon planning (~20s)
    AGENT_TASK_TIMEOUT = 180
    # Interval polling status task agent (detik)
    POLL_INTERVAL = 3.0

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.manager = AgentManager(session)
        self.registry = TechniqueRegistry.instance()

    async def dispatch(
        self,
        technique_id: str,
        target_ip: str,
        campaign_id: str | None = None,
        scope_ips: list[str] | None = None,
        scope_domains: list[str] | None = None,
        excluded_targets: list[str] | None = None,
        production_safe_mode: bool = True,
        extra_context: dict | None = None,
        prefer_agent: bool = True,
    ) -> DispatchResult:
        """
        Dispatch eksekusi teknik ke agent atau simulasi.

        Args:
            technique_id:         ATT&CK technique ID
            target_ip:            IP target eksekusi
            campaign_id:          ID kampanye (untuk routing agent)
            scope_ips:            Daftar IP/CIDR yang diizinkan
            scope_domains:        Domain yang diizinkan
            excluded_targets:     Target yang dikecualikan
            production_safe_mode: Blokir teknik destruktif di OT
            extra_context:        Context tambahan untuk teknik
            prefer_agent:         Prioritaskan agent jika tersedia

        Returns:
            DispatchResult dengan status dan output
        """
        extra_context = extra_context or {}
        agent_type = "ot" if extra_context.get("ot_channel") or extra_context.get("protocol") else "it"

        # 1. Coba routing ke agent
        if prefer_agent:
            agent = await self.manager.find_agent_for_target(
                target_ip=target_ip,
                campaign_id=campaign_id,
                agent_type=agent_type,
            )
            if agent and agent.is_active:
                logger.info(
                    "Dispatch via agent: technique={} target={} agent={}",
                    technique_id, target_ip, agent.hostname,
                )
                return await self._dispatch_to_agent(
                    agent=agent,
                    technique_id=technique_id,
                    target_ip=target_ip,
                    campaign_id=campaign_id,
                    extra_context=extra_context,
                )

        # 2. Registry execution (simulasi konkret)
        return await self._dispatch_via_registry_or_simulation(
            technique_id=technique_id,
            target_ip=target_ip,
            scope_ips=scope_ips or [],
            scope_domains=scope_domains or [],
            excluded_targets=excluded_targets or [],
            campaign_id=campaign_id or "",
            production_safe_mode=production_safe_mode,
            extra_context=extra_context,
        )

    async def _dispatch_to_agent(
        self,
        agent: Agent,
        technique_id: str,
        target_ip: str,
        campaign_id: str | None,
        extra_context: dict,
    ) -> DispatchResult:
        """
        Route eksekusi ke agent yang terdaftar.

        Flow:
        1. Ambil info teknik dari DB
        2. Shannon AI merencanakan perintah konkret berdasarkan teknik + OS agent
        3. Queue perintah nyata ke agent (bukan "execute_technique" generik)
        4. Tunggu hasil dan format output
        """
        from core.config import Settings
        settings = Settings()  # baca langsung dari .env, hindari lru_cache stale

        # Ambil detail teknik dari DB untuk konteks Shannon
        tech_info = await self._get_technique_info(technique_id)

        # Gunakan override_command jika user sudah validasi & edit di frontend
        if extra_context.get("override_command"):
            plan = {
                "task_type": extra_context.get("override_task_type", "shell_command"),
                "command": extra_context["override_command"],
                "explanation": "User-validated command (edited from Shannon recommendation)",
            }
            logger.info("Using user override command for {}: {}", technique_id, plan["command"][:80])
        else:
            # Shannon merencanakan perintah yang tepat untuk teknik ini
            plan = await self._plan_with_shannon(technique_id, tech_info, agent, settings)

        # Log rencana Shannon
        logger.info(
            "Shannon plan untuk {} on {} ({}): type={} command={}",
            technique_id, agent.hostname, agent.os_type,
            plan["task_type"], plan["command"][:80],
        )

        # Queue task dengan perintah nyata yang direncanakan Shannon
        task_params = self._build_task_params(plan["task_type"], plan["command"])
        task = await self.manager.queue_task(
            agent_id=agent.id,
            task_type=plan["task_type"],
            technique_id=technique_id,
            task_params=task_params,
            campaign_id=campaign_id,
            priority=5,
            timeout_seconds=self.AGENT_TASK_TIMEOUT,
        )

        # Enrich context dengan info agent
        enriched_context = self._enrich_context_from_agent(agent, extra_context)
        enriched_context["shannon_plan"] = plan

        # Tunggu hasil task dari agent (dengan timeout)
        start_time = datetime.now(timezone.utc)
        elapsed = 0.0

        while elapsed < self.AGENT_TASK_TIMEOUT:
            await asyncio.sleep(self.POLL_INTERVAL)

            # Refresh task dari DB — HARUS pakai populate_existing=True
            # karena SQLAlchemy identity map cache akan mengembalikan objek lama
            # dari memori tanpa re-query ke DB, sehingga status tidak pernah update.
            from sqlalchemy import select
            from core.models.agent import AgentTask
            task_result = await self.session.execute(
                select(AgentTask)
                .where(AgentTask.id == task.id)
                .execution_options(populate_existing=True)
            )
            refreshed_task = task_result.scalar_one_or_none()

            if refreshed_task and refreshed_task.is_terminal:
                elapsed_total = (
                    datetime.now(timezone.utc) - start_time
                ).total_seconds()

                status = ExecutionStatus.SUCCESS if refreshed_task.result_status == "success" else (
                    ExecutionStatus.PARTIAL if refreshed_task.result_status == "partial"
                    else ExecutionStatus.FAILED
                )

                logger.info(
                    "Agent task selesai: {} agent={} status={} t={:.1f}s",
                    technique_id, agent.hostname, status.value, elapsed_total,
                )
                # Format output dengan konteks Shannon
                raw_output = refreshed_task.result_output or ""
                explanation = enriched_context.get("shannon_plan", {}).get("explanation", "")
                command_used = enriched_context.get("shannon_plan", {}).get("command", "")

                header = (
                    f"[Agent: {agent.hostname} | OS: {agent.os_type} | "
                    f"Privilege: {agent.privilege_level}]\n"
                    f"[Technique: {technique_id} — {tech_info.get('name', '')}]\n"
                )
                if command_used:
                    header += f"[Command: {command_used}]\n"
                if explanation:
                    header += f"[Rationale: {explanation}]\n"
                header += "─" * 60 + "\n"

                return DispatchResult(
                    technique_id=technique_id,
                    target=target_ip,
                    status=status,
                    output=header + raw_output,
                    error=refreshed_task.error_message or "",
                    artifacts=refreshed_task.artifacts,
                    collected_data=refreshed_task.collected_data,
                    duration_seconds=refreshed_task.duration_seconds,
                    dispatched_via="agent",
                    agent_id=agent.id,
                    task_id=task.id,
                )

            elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

        # Timeout — agent tidak merespons dalam waktu yang ditentukan
        logger.warning(
            "Agent task timeout: {} agent={} ({}s)",
            technique_id, agent.hostname, self.AGENT_TASK_TIMEOUT,
        )
        # Mark task sebagai timeout
        from sqlalchemy import select
        from core.models.agent import AgentTask
        task_check = await self.session.execute(
            select(AgentTask).where(AgentTask.id == task.id)
        )
        timed_out_task = task_check.scalar_one_or_none()
        if timed_out_task and not timed_out_task.is_terminal:
            timed_out_task.status = "timeout"
            await self.session.commit()

        # Fallback ke registry/simulasi setelah timeout
        logger.info("Fallback ke simulasi setelah agent timeout.")
        return await self._dispatch_via_registry_or_simulation(
            technique_id=technique_id,
            target_ip=target_ip,
            scope_ips=[],
            scope_domains=[],
            excluded_targets=[],
            campaign_id=campaign_id or "",
            production_safe_mode=True,
            extra_context=enriched_context,
        )

    async def _get_technique_info(self, technique_id: str) -> dict:
        """Ambil nama, deskripsi, taktik dari DB untuk konteks Shannon."""
        from sqlalchemy import select as sa_select
        from core.models.technique import Technique
        try:
            result = await self.session.execute(
                sa_select(Technique).where(Technique.id == technique_id.upper())
            )
            t = result.scalar_one_or_none()
            if t:
                return {
                    "name": t.name,
                    "description": (t.description or "")[:800],
                    "tactic": t.tactic,
                    "platforms": t.platforms,
                    "detection_note": t.detection_note or "",
                }
        except Exception as e:
            logger.warning("Gagal ambil info teknik {}: {}", technique_id, e)
        return {"name": technique_id, "description": "", "tactic": "", "platforms": [], "detection_note": ""}

    async def _plan_with_shannon(
        self,
        technique_id: str,
        tech_info: dict,
        agent: Agent,
        settings: Any,
    ) -> dict:
        """
        Minta Shannon AI merencanakan perintah konkret untuk teknik ini di agent ini.

        Returns dict:
            task_type:   "shell_command" | "powershell" | "python_exec"
            command:     string perintah yang akan dijalankan
            explanation: alasan memilih perintah ini
        """
        if not settings.has_shannon_configured:
            return self._fallback_plan(technique_id, agent)

        caps = agent.capabilities or []
        has_ps = any(c in caps for c in ("powershell", "execute_powershell"))
        has_shell = "shell" in caps
        os_type = agent.os_type or "unknown"
        privilege = agent.privilege_level or "user"

        system_prompt = (
            "You are a red team execution planner embedded in an authorized adversary emulation platform. "
            "Given an ATT&CK technique and a connected agent, determine the single best command to run.\n\n"
            "CRITICAL — command must execute successfully with NO extra dependencies:\n"
            "- python_exec: ONLY Python standard library (socket, subprocess, os, sys, ctypes, winreg, struct, "
            "ipaddress, platform, pathlib, shutil, glob, re, json, base64, hashlib, threading, etc.). "
            "NEVER use third-party packages (netifaces, impacket, psutil, requests, paramiko, scapy, etc.). "
            "For network info: subprocess.check_output(['ipconfig','/all']).decode() on Windows, "
            "or socket.gethostbyname_ex(socket.gethostname()). "
            "For process list: subprocess.check_output(['tasklist']).decode().\n"
            "- powershell: use built-in PowerShell cmdlets only.\n"
            "- shell_command: use native OS binaries (ipconfig, netstat, tasklist, net, reg, wmic on Windows; "
            "ip, ss, ps, id, uname on Linux). No pip, no apt, no external downloads.\n"
            "Be specific — output REAL runnable commands. No interactive input, no GUI. Respond with JSON only."
        )

        user_prompt = (
            f"Plan execution for this ATT&CK technique on the connected agent:\n\n"
            f"Technique: {technique_id} — {tech_info.get('name', technique_id)}\n"
            f"Tactic: {tech_info.get('tactic', 'unknown')}\n"
            f"Description: {tech_info.get('description', '')[:400]}\n\n"
            f"Agent info:\n"
            f"  OS: {os_type}\n"
            f"  Privilege: {privilege}\n"
            f"  Capabilities: {', '.join(caps) or 'shell'}\n\n"
            f"Available task types:\n"
            f"  shell_command — run via cmd.exe (Windows) or /bin/sh (Linux/macOS)\n"
            f"  powershell    — run via PowerShell (only if 'powershell' in capabilities)\n"
            f"  python_exec   — Python code; write ONLY the raw Python statements, no 'python -c' wrapper,\n"
            f"                  no quotes around the code — the platform wraps it automatically.\n\n"
            f"Return JSON:\n"
            f'{{"task_type": "shell_command"|"powershell"|"python_exec", '
            f'"command": "the exact command or raw Python code (no python -c wrapper)", '
            f'"explanation": "one sentence: why this command, what it discovers/does"}}'
        )

        try:
            data = await self._shannon_post(
                settings=settings,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=512,
                response_format={"type": "json_object"},
                timeout=40.0,
            )
            raw = data["choices"][0]["message"]["content"]
            plan = _json.loads(raw)

            # Validasi task_type
            valid_types = {"shell_command", "powershell", "python_exec"}
            if plan.get("task_type") not in valid_types:
                plan["task_type"] = "shell_command"
            if plan.get("task_type") == "powershell" and not has_ps:
                plan["task_type"] = "shell_command"

            # Downgrade python_exec commands that use third-party modules
            plan = _sanitize_python_command(plan, os_type)
            # Wrap python_exec as 'python -c "..."' shell command so it's copy-paste ready
            plan = _wrap_python_exec_as_shell(plan, os_type)

            return plan

        except Exception as e:
            logger.warning("Shannon planning gagal untuk {}: {} — pakai fallback", technique_id, e)
            return self._fallback_plan(technique_id, agent)

    @staticmethod
    async def _shannon_post(
        settings: Any,
        messages: list[dict],
        max_tokens: int = 1200,
        response_format: dict | None = None,
        timeout: float = 45.0,
        max_retries: int = 4,
    ) -> dict:
        """
        POST ke Shannon API dengan retry eksponensial pada 429 rate-limit.
        Raises httpx.HTTPStatusError pada error non-recoverable.
        """
        import httpx

        headers = {
            "Authorization": f"Bearer {settings.shannon_api_key}",
            "Content-Type": "application/json",
        }
        payload: dict = {
            "model": settings.shannon_model,
            "messages": messages,
            "max_tokens": max_tokens,
        }
        if response_format:
            payload["response_format"] = response_format

        # Backoff schedule untuk 429: 30s, 60s, 60s, 60s — total max ~3.5 menit
        _429_backoff = [30, 60, 60, 60]

        last_exc: Exception | None = None
        for attempt in range(max_retries):
            try:
                # Jaga minimum spacing antar request agar tidak langsung memicu 429
                await _shannon_rl.wait()

                async with httpx.AsyncClient(timeout=timeout) as client:
                    resp = await client.post(
                        f"{settings.shannon_base_url}/chat/completions",
                        headers=headers,
                        json=payload,
                    )
                    if resp.status_code == 429:
                        # Honour Retry-After header jika ada; jika tidak, pakai jadwal backoff
                        retry_after_hdr = resp.headers.get("Retry-After")
                        if retry_after_hdr:
                            retry_after = int(retry_after_hdr)
                        else:
                            retry_after = _429_backoff[min(attempt, len(_429_backoff) - 1)]
                        logger.warning(
                            "Shannon 429 rate-limit — attempt {}/{}, tunggu {}s",
                            attempt + 1, max_retries, retry_after,
                        )
                        # Reset last_call agar rate limiter tidak menghitung wait ini
                        _shannon_rl._last_call = 0.0
                        await asyncio.sleep(retry_after)
                        last_exc = Exception(
                            f"Shannon API sedang rate-limited (429). "
                            f"Sudah mencoba {attempt + 1}x. Coba lagi dalam beberapa saat."
                        )
                        continue
                    resp.raise_for_status()
                    return resp.json()
            except httpx.HTTPStatusError as e:
                code = e.response.status_code
                if code == 402:
                    raise Exception(
                        "Shannon quota habis (402 Quota Exceeded). "
                        "Periksa saldo token di dashboard Shannon AI."
                    ) from e
                if attempt < max_retries - 1:
                    wait = min(2 ** attempt, 30)
                    logger.warning("Shannon HTTP {} — retry in {}s: {}", code, wait, e)
                    await asyncio.sleep(wait)
                    last_exc = e
                else:
                    raise
            except Exception as e:
                if attempt < max_retries - 1:
                    await asyncio.sleep(min(2 ** attempt, 15))
                    last_exc = e
                else:
                    raise
        raise last_exc or Exception("Shannon API tidak dapat dihubungi setelah beberapa retry")

    async def plan_with_alternatives(
        self,
        technique_id: str,
        tech_info: dict,
        agent: "Agent | None",
        settings: Any,
        evasion_context: str | None = None,
    ) -> dict:
        """
        Versi plan yang mengembalikan primary command + 2-3 alternatif.
        Digunakan oleh /plan endpoint (preview sebelum eksekusi).

        Returns dict:
            primary:      {task_type, command, explanation}
            alternatives: [{label, task_type, command, explanation}, ...]
        """
        # Jika Shannon tidak dikonfigurasi sama sekali, pakai fallback statis
        if not settings.has_shannon_configured:
            return {"primary": self._fallback_plan(technique_id, agent), "alternatives": []}

        # Tentukan konteks eksekusi — agent (jika ada) atau mode simulasi
        if agent is not None:
            caps = agent.capabilities or []
            os_type = agent.os_type or "windows"
            privilege = agent.privilege_level or "user"
            has_ps = any(c in caps for c in ("powershell", "execute_powershell"))
            has_py = any(c in caps for c in ("python_exec", "execute_python"))
            available_types = ["shell_command"]
            if has_ps:
                available_types.append("powershell")
            if has_py:
                available_types.append("python_exec")
            context_desc = (
                f"Target agent: OS={os_type}, Privilege={privilege}, "
                f"Capabilities={', '.join(caps) or 'shell'}\n"
                f"Available task types: {', '.join(available_types)}\n"
                f"Commands will be executed directly on the agent — choose task_type accordingly."
            )
        else:
            # Tidak ada agent — Shannon tetap kasih rekomendasi payload realistis
            os_type = "windows"
            has_ps = True
            available_types = ["shell_command", "powershell", "python_exec"]
            context_desc = (
                "No live agent at target — this is simulation mode.\n"
                "Suggest realistic payloads that an attacker would actually use for this technique.\n"
                "Available task types: shell_command, powershell, python_exec\n"
                "Use task_type='simulation' for the primary if you want to indicate this is illustrative."
            )

        system_prompt = (
            "You are a red team execution planner for an authorized adversary emulation platform. "
            "Suggest one primary payload/command AND exactly 5 alternative approaches for the given ATT&CK technique.\n\n"
            "CRITICAL RULES — commands must work out-of-the-box with no extra setup:\n"
            "1. python_exec commands: use ONLY Python standard library modules "
            "(socket, subprocess, os, sys, ctypes, winreg, struct, ipaddress, platform, shutil, pathlib, etc.). "
            "NEVER use pip-installable packages like netifaces, impacket, psutil, requests, paramiko, scapy, etc. "
            "If you need network info on Windows use: subprocess.check_output(['ipconfig','/all']).decode(). "
            "If you need process info use: subprocess.check_output(['tasklist']).decode(). "
            "For registry: use winreg module. For sockets: use socket module.\n"
            "2. powershell commands: use built-in cmdlets only (Get-NetIPConfiguration, Get-Process, etc.). "
            "For staged payloads that need external tools, use IEX+DownloadString to load from http://192.168.1.100/tool.ps1.\n"
            "3. shell_command: use native OS binaries only (ipconfig, net, netstat, tasklist, reg, wmic on Windows; "
            "ip, ss, ps, id, uname, cat on Linux). No tool installation.\n"
            "4. No interactive/GUI commands. No placeholders. Respond with valid JSON only."
        )

        evasion_note = (
            f"\n\nIMPORTANT — EVASION/RETRY CONTEXT:\n{evasion_context}\n"
            "Given this context, prioritize evasive or alternative approaches. "
            "Your primary should be meaningfully different from the failed attempt. "
            "Focus alternatives on: different tooling, living-off-the-land, obfuscation, "
            "or timing/staging approaches that would evade the detected control."
        ) if evasion_context else ""

        user_prompt = (
            f"ATT&CK Technique: {technique_id} — {tech_info.get('name', technique_id)}\n"
            f"Tactic: {tech_info.get('tactic', '')}\n"
            f"Description: {tech_info.get('description', '')[:500]}\n\n"
            f"{context_desc}{evasion_note}\n\n"
            f"Return JSON with this exact structure (provide exactly 5 alternatives):\n"
            '{{"primary": {{"task_type": "shell_command|powershell|python_exec|simulation", '
            '"command": "for shell_command/powershell: the full runnable command; '
            'for python_exec: ONLY raw Python statements (no python -c wrapper, no surrounding quotes) — '
            'use REAL URLs like http://192.168.1.100/script.ps1 for staged payloads", '
            '"explanation": "one sentence: what this does and why it\'s effective"}},'
            '"alternatives": ['
            '{{"label": "Short variant name (e.g. PowerShell WMI, Python subprocess, LOLBin, CrackMapExec)", '
            '"task_type": "shell_command|powershell|python_exec", '
            '"command": "full realistic command (python_exec: raw Python only)", '
            '"explanation": "when to use this variant — stealth/noise tradeoff"}},'
            "... exactly 5 alternative variants"
            "]}}"
        )

        try:
            data = await self._shannon_post(
                settings=settings,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=2000,
                response_format={"type": "json_object"},
                timeout=60.0,
            )
            result = _json.loads(data["choices"][0]["message"]["content"])

            # Validasi dan sanitize primary
            valid_types = {"shell_command", "powershell", "python_exec", "simulation"}
            primary = result.get("primary", {})
            if not primary.get("command"):
                raise ValueError("Shannon returned empty primary command")
            if primary.get("task_type") not in valid_types:
                primary["task_type"] = "shell_command"
            if primary.get("task_type") == "powershell" and not has_ps and agent is not None:
                primary["task_type"] = "shell_command"

            # Sanitize: downgrade third-party imports, then wrap as python -c "..."
            primary = _sanitize_python_command(primary, os_type)
            primary = _wrap_python_exec_as_shell(primary, os_type)

            # Validasi alternatives (max 5)
            alternatives = []
            for alt in result.get("alternatives", []):
                if not isinstance(alt, dict) or not alt.get("command"):
                    continue
                if alt.get("task_type") not in valid_types:
                    alt["task_type"] = "shell_command"
                if alt.get("task_type") == "powershell" and not has_ps and agent is not None:
                    alt["task_type"] = "shell_command"
                alt = _sanitize_python_command(alt, os_type)
                alt = _wrap_python_exec_as_shell(alt, os_type)
                alternatives.append(alt)

            return {"primary": primary, "alternatives": alternatives[:5]}

        except Exception as e:
            msg = str(e)
            # Re-raise rate-limit / quota errors so caller can surface to user
            if "rate-limited" in msg.lower() or "429" in msg or "quota" in msg.lower() or "402" in msg:
                logger.error("Shannon rate-limit/quota error untuk {}: {}", technique_id, e)
                raise
            logger.error("Shannon plan_with_alternatives gagal untuk {}: {}", technique_id, e)
            fallback = self._fallback_plan(technique_id, agent)
            return {"primary": fallback, "alternatives": []}

    @staticmethod
    def _fallback_plan(technique_id: str, agent: "Agent | None") -> dict:
        """Fallback command plan saat Shannon tidak tersedia."""
        if agent is None:
            return {
                "task_type": "simulation",
                "command": f"# Shannon AI simulation for {technique_id}",
                "explanation": "No agent available — will run Shannon AI simulation.",
            }
        os_type = (agent.os_type or "unknown").lower()
        caps = agent.capabilities or []
        has_ps = any(c in caps for c in ("powershell", "execute_powershell"))

        # Minimal fallback commands per taktik berdasarkan teknik ID prefix
        # T0xxx = ICS, T1xxx = Enterprise IT
        if os_type == "windows":
            if has_ps:
                return {
                    "task_type": "powershell",
                    "command": "Get-ComputerInfo | Select-Object CsName,OsName,OsVersion,CsProcessors; Get-Service | Select-Object Name,Status | Format-Table -AutoSize",
                    "explanation": "Basic system and service discovery (fallback — Shannon not configured)",
                }
            return {
                "task_type": "shell_command",
                "command": "systeminfo && net user && net localgroup administrators && ipconfig /all && netstat -an",
                "explanation": "Basic Windows discovery (fallback)",
            }
        else:
            return {
                "task_type": "shell_command",
                "command": "uname -a && id && whoami && ps aux | head -20 && ss -tlnp && ip addr",
                "explanation": "Basic Linux/macOS discovery (fallback)",
            }

    @staticmethod
    def _build_task_params(task_type: str, command: str) -> dict:
        """Bangun task_params yang sesuai untuk setiap task_type."""
        if task_type == "powershell":
            return {"script": command, "timeout": 60}
        elif task_type == "python_exec":
            return {"code": command, "timeout": 60}
        else:  # shell_command
            return {"command": command, "timeout": 60}

    async def _dispatch_via_registry_or_simulation(
        self,
        technique_id: str,
        target_ip: str,
        scope_ips: list[str],
        scope_domains: list[str],
        excluded_targets: list[str],
        campaign_id: str,
        production_safe_mode: bool,
        extra_context: dict,
    ) -> DispatchResult:
        """Eksekusi teknik melalui registry atau simulasi probabilistik."""
        technique_impl = self.registry.get(technique_id)

        if technique_impl:
            # Registry execution (simulasi konkret dengan logika yang sudah diimplementasikan)
            ctx = TechniqueContext(
                target_host=target_ip,
                campaign_id=campaign_id,
                scope_ips=scope_ips,
                scope_domains=scope_domains,
                excluded_targets=excluded_targets,
                production_safe_mode=production_safe_mode,
                extra=extra_context,
            )
            result: TechniqueResult = await technique_impl.run(ctx)
            return DispatchResult(
                technique_id=technique_id,
                target=target_ip,
                status=result.status,
                output=result.output,
                error=result.error,
                artifacts=result.artifacts_created,
                collected_data=result.collected_data,
                duration_seconds=result.duration_seconds,
                dispatched_via="registry",
            )

        # Shannon AI simulation — generate realistic output untuk teknik tanpa implementasi
        return await self._dispatch_via_shannon(
            technique_id=technique_id,
            target_ip=target_ip,
            extra_context=extra_context,
        )

    async def _dispatch_via_shannon(
        self,
        technique_id: str,
        target_ip: str,
        extra_context: dict,
    ) -> DispatchResult:
        """
        Generate output simulasi realistis menggunakan Shannon AI.
        Digunakan sebagai fallback ketika tidak ada agent dan tidak ada registry impl.
        """
        # Re-read settings setiap kali — jangan pakai lru_cache di hot path ini
        # karena lru_cache mungkin sudah stale jika server baru saja restart
        from core.config import Settings
        settings = Settings()  # baca ulang dari .env langsung

        logger.info(
            "Shannon dispatch: configured={} key={}",
            settings.has_shannon_configured,
            f"{settings.shannon_api_key[:8]}..." if settings.shannon_api_key else "NONE",
        )

        if settings.has_shannon_configured:
            try:
                tech_info = await self._get_technique_info(technique_id)
                output = await self._call_shannon_simulation(
                    technique_id=technique_id,
                    tech_info=tech_info,
                    target_ip=target_ip,
                    extra_context=extra_context,
                    settings=settings,
                )
                return DispatchResult(
                    technique_id=technique_id,
                    target=target_ip,
                    status=ExecutionStatus.SUCCESS,
                    output=output,
                    dispatched_via="shannon_ai",
                )
            except Exception as e:
                logger.error(
                    "Shannon AI simulation GAGAL untuk {} — error: {} {}",
                    technique_id, type(e).__name__, e,
                )
                # Kembalikan error sebagai output agar user tahu apa yang salah
                return DispatchResult(
                    technique_id=technique_id,
                    target=target_ip,
                    status=ExecutionStatus.FAILED,
                    output=(
                        f"[Shannon AI Error] {technique_id} pada {target_ip}\n"
                        f"Error: {type(e).__name__}: {e}\n"
                        f"Shannon API URL: {settings.shannon_base_url}\n"
                        f"Model: {settings.shannon_model}"
                    ),
                    error=str(e),
                    dispatched_via="shannon_ai",
                )

        # Shannon tidak dikonfigurasi — info jelas ke user
        return DispatchResult(
            technique_id=technique_id,
            target=target_ip,
            status=ExecutionStatus.FAILED,
            output=(
                f"[Shannon AI tidak dikonfigurasi]\n"
                f"Teknik {technique_id} tidak ada di registry dan SHANNON_API_KEY belum di-set.\n"
                f"Tambahkan ke .env:\n"
                f"  SHANNON_API_KEY=sk-...\n"
                f"  SHANNON_BASE_URL=https://api.shannon-ai.com/v1\n"
                f"  SHANNON_MODEL=shannon-1.6-pro"
            ),
            dispatched_via="simulation",
        )

    @staticmethod
    async def _call_shannon_simulation(
        technique_id: str,
        tech_info: dict,
        target_ip: str,
        extra_context: dict,
        settings: Any,
    ) -> str:
        """
        Panggil Shannon AI untuk mensimulasikan eksekusi teknik dan return output terminal.
        Mode ini digunakan ketika tidak ada agent — Shannon generate output realistis.
        """
        tech_name = tech_info.get("name", technique_id)
        tactic = tech_info.get("tactic", "")
        description = tech_info.get("description", "")[:400]
        target_os = extra_context.get("agent_os") or extra_context.get("target_os", "Windows")
        privilege = extra_context.get("agent_privilege", "user")
        protocol = extra_context.get("protocol", "")

        ot_context = ""
        if protocol:
            ot_context = f"\nOT context: Protocol={protocol}. This is an ICS/OT target."

        system_prompt = (
            "You are a red team execution engine simulating an authorized engagement. "
            "Simulate realistic terminal/tool output for an ATT&CK technique. "
            "Output ONLY the terminal output — no explanations, no markdown. "
            "Be specific: use realistic hostnames, service names, user accounts, IPs. "
            "First line: show the command that was run. Then show realistic output."
        )

        user_prompt = (
            f"Simulate executing ATT&CK {technique_id} ({tech_name}) against {target_ip}.\n"
            f"Tactic: {tactic}\n"
            f"Technique description: {description}\n"
            f"Target OS: {target_os}, Privilege: {privilege}.{ot_context}\n\n"
            f"Show: the command run + realistic output (30-100 lines). No explanations."
        )

        data = await self._shannon_post(
            settings=settings,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=1500,
            timeout=60.0,
        )
        raw = data["choices"][0]["message"]["content"].strip()
        header = (
            f"[Shannon AI Simulation — No agent at {target_ip}]\n"
            f"[Technique: {technique_id} — {tech_name} | Tactic: {tactic}]\n"
            + "─" * 60 + "\n"
        )
        return header + raw

    async def generate_script(
        self,
        technique_id: str,
        tech_info: dict,
        script_url: str,
        command_context: str,
        settings: Any,
    ) -> dict:
        """
        Minta Shannon menulis konten script yang dirujuk dalam payload.
        Contoh: jika command berisi 'http://192.168.1.100/Invoke-Mimikatz.ps1',
        Shannon akan menulis konten Invoke-Mimikatz.ps1 yang realistis.

        Returns:
            {filename, extension, language, content, description}
        """
        import posixpath
        import re

        # Ekstrak nama file dari URL
        filename = posixpath.basename(script_url.split("?")[0]) or "payload"
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "sh"

        lang_map = {
            "ps1": "powershell", "py": "python", "sh": "bash",
            "bat": "batch", "vbs": "vbscript", "rb": "ruby",
            "php": "php", "js": "javascript",
        }
        language = lang_map.get(ext, "text")

        if not settings.has_shannon_configured:
            stub = f"# Script: {filename}\n# Shannon AI not configured — cannot generate content\n"
            return {"filename": filename, "extension": ext, "language": language,
                    "content": stub, "description": "Shannon not configured"}

        system_prompt = (
            "You are a script generator for an authorized red team platform. "
            "Your response must be ONLY the raw script content — nothing else. "
            "STRICT RULES:\n"
            "1. Do NOT write your name, role, or any preamble like 'SHANNON:', 'Here is the script:', etc.\n"
            "2. Do NOT wrap the script in markdown code fences (no ```).\n"
            "3. Start your response with the very first line of the script itself (e.g. a comment header or the first statement).\n"
            "4. The script must be complete, functional, and ready to save directly to a file and run.\n"
            "5. Use inline comments inside the script to explain what each section does.\n"
            "6. Do NOT include any text after the last line of the script."
        )

        comment_char = {"powershell": "#", "python": "#", "bash": "#",
                        "batch": "REM", "vbscript": "'", "ruby": "#",
                        "php": "//", "javascript": "//", "text": "#"}.get(language, "#")

        user_prompt = (
            f"Generate the file: {filename}\n"
            f"Language: {language}\n"
            f"ATT&CK: {technique_id} — {tech_info.get('name', technique_id)} | {tech_info.get('tactic', '')}\n"
            f"Command context that downloads/references this script:\n{command_context[:600]}\n\n"
            f"Start the file with a {comment_char} comment block: filename, technique, date, purpose.\n"
            f"Then write the full working implementation.\n"
            f"Technique description: {tech_info.get('description', '')[:300]}\n\n"
            f"REMEMBER: output ONLY the raw {language} script. No markdown, no preamble, no explanation."
        )

        def _clean_script_output(raw: str) -> str:
            """
            Robustly extract script content from Shannon's response.
            Handles:
            - 'SHANNON-Ω:' or any 'Name:' preamble lines before the code
            - Markdown code fences (``` anywhere in the response)
            - Trailing commentary after the code
            """
            text = raw.strip()

            # If there's a fenced code block anywhere, extract just that content
            fence_match = re.search(r"```[a-zA-Z]*\n(.*?)```", text, re.DOTALL)
            if fence_match:
                return fence_match.group(1).strip()

            # No fences — strip leading preamble lines (lines before first code-like line)
            lines = text.splitlines()
            start = 0
            for i, line in enumerate(lines):
                stripped = line.strip()
                if not stripped:
                    continue
                # A "preamble" line looks like: "Name:", "Here is...", etc.
                # Code starts with: #, $, import, function, def, param, <, REM, //, etc.
                code_starters = ("#", "$", "import ", "from ", "function ", "def ", "param",
                                 "param(", "<", "REM ", "//", "Set ", "Dim ", "<?", "require",
                                 "use ", "@", "class ", "module ", "echo ", "#!/", "param ")
                is_preamble = (
                    (":" in stripped and len(stripped) < 80 and not stripped.startswith("#"))
                    or stripped.lower().startswith(("here is", "here's", "below is",
                                                    "the following", "this script", "sure,", "certainly"))
                )
                if is_preamble:
                    start = i + 1
                else:
                    break  # found first real code line

            result = "\n".join(lines[start:]).strip()
            # Final safety: strip any remaining leading ``` if the fence_match missed it
            result = re.sub(r"^```[a-zA-Z]*\n?", "", result)
            result = re.sub(r"\n?```\s*$", "", result)
            return result.strip()

        try:
            data = await self._shannon_post(
                settings=settings,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=2500,
                timeout=60.0,
            )
            raw = data["choices"][0]["message"]["content"]
            content = _clean_script_output(raw)

            return {
                "filename": filename,
                "extension": ext,
                "language": language,
                "content": content.strip(),
                "description": f"Generated by Shannon AI for {technique_id}",
            }

        except Exception as e:
            logger.error("Shannon generate_script gagal untuk {}: {}", filename, e)
            stub = f"# Script: {filename}\n# Generation failed: {e}\n"
            return {"filename": filename, "extension": ext, "language": language,
                    "content": stub, "description": f"Error: {e}"}

    @staticmethod
    def _enrich_context_from_agent(agent: Agent, base_context: dict) -> dict:
        """Tambah informasi dari agent ke context eksekusi."""
        enriched = dict(base_context)
        enriched.update({
            "agent_id": agent.id,
            "agent_hostname": agent.hostname,
            "agent_os": agent.os_type,
            "agent_privilege": agent.privilege_level,
            "has_admin": agent.has_elevated,
            "agent_capabilities": agent.capabilities,
        })
        # Inject OT context jika agen OT
        if agent.agent_type == "ot" and agent.ot_protocol:
            enriched["protocol"] = agent.ot_protocol
        return enriched
