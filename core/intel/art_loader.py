"""
Atomic Red Team (ART) local library loader.

Parses atomics/{technique_id}/{technique_id}.yaml dan mengembalikan
daftar test yang siap digunakan sebagai command payloads.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

from loguru import logger

# Folder atomics relatif ke root project (dua level atas core/)
_ATOMICS_DIR = Path(__file__).parent.parent.parent / "atomics"

# Mapping ART executor → platform task_type kita
_EXECUTOR_MAP: dict[str, str | None] = {
    "command_prompt": "shell_command",
    "powershell":     "powershell",
    "sh":             "shell_command",
    "bash":           "shell_command",
    "manual":         None,   # skip — butuh operator manual
}

# Platform filter — kita hanya support ini untuk sekarang
_SUPPORTED_PLATFORMS = {"windows", "linux", "macos"}


def _resolve_args(command: str, input_arguments: dict[str, Any]) -> str:
    """Substitusi #{arg_name} dengan default value dari input_arguments."""
    for arg_name, arg_info in input_arguments.items():
        default = str(arg_info.get("default", f"<{arg_name}>"))
        # Ganti PathToAtomicsFolder dengan path absolut lokal
        default = default.replace("PathToAtomicsFolder", str(_ATOMICS_DIR))
        command = command.replace(f"#{{{arg_name}}}", default)
    # Bersihkan sisa placeholder yang tidak ter-resolve
    command = re.sub(r"#\{[^}]+\}", "<ARG>", command)
    return command.strip()


def load_atomic_tests(
    technique_id: str,
    platform_filter: str | None = None,
) -> list[dict]:
    """
    Load dan parse ART tests untuk technique_id dari YAML lokal.

    Args:
        technique_id: e.g. "T1003.001"
        platform_filter: "windows" | "linux" | "macos" | None (semua)

    Returns:
        List of normalized test dicts:
        {
            guid, name, description, task_type, command,
            cleanup_command, elevation_required, platforms,
            source: "art"
        }
    """
    if not _HAS_YAML:
        logger.warning("PyYAML tidak tersedia — ART loader dinonaktifkan. Install dengan: pip install pyyaml")
        return []

    yaml_path = _ATOMICS_DIR / technique_id / f"{technique_id}.yaml"
    if not yaml_path.exists():
        return []

    try:
        with open(yaml_path, encoding="utf-8") as f:
            data = _yaml.safe_load(f)
    except Exception as e:
        logger.warning("Gagal parse ART YAML {}: {}", yaml_path, e)
        return []

    tests: list[dict] = []
    for test in data.get("atomic_tests", []):
        executor = test.get("executor") or {}
        executor_name = executor.get("name", "")
        task_type = _EXECUTOR_MAP.get(executor_name)
        if task_type is None:
            continue  # skip manual tests

        command = executor.get("command", "").strip()
        if not command:
            continue

        platforms = [p.lower() for p in test.get("supported_platforms", [])]
        # Filter platform jika diminta
        if platform_filter and platform_filter.lower() not in platforms:
            continue
        # Skip platform yang tidak kita support sama sekali
        if platforms and not any(p in _SUPPORTED_PLATFORMS for p in platforms):
            continue

        # Resolve input_arguments defaults
        input_args = test.get("input_arguments") or {}
        command = _resolve_args(command, input_args)

        cleanup = executor.get("cleanup_command", "").strip()
        if cleanup:
            cleanup = _resolve_args(cleanup, input_args)

        description = (test.get("description") or "").strip()

        tests.append({
            "guid": test.get("auto_generated_guid", ""),
            "name": test.get("name", ""),
            "description": description[:250] if description else "",
            "task_type": task_type,
            "command": command,
            "cleanup_command": cleanup,
            "elevation_required": executor.get("elevation_required", False),
            "platforms": platforms,
            "source": "art",
        })

    return tests


@lru_cache(maxsize=512)
def load_atomic_tests_cached(technique_id: str, platform_filter: str | None = None) -> tuple[dict, ...]:
    """Cached version — returns tuple (hashable) instead of list."""
    return tuple(load_atomic_tests(technique_id, platform_filter))


def has_atomic_tests(technique_id: str) -> bool:
    """Quick check apakah ART punya tests untuk teknik ini."""
    yaml_path = _ATOMICS_DIR / technique_id / f"{technique_id}.yaml"
    return yaml_path.exists()


def format_art_for_shannon(tests: list[dict]) -> str:
    """
    Format ART tests sebagai teks konteks untuk dimasukkan ke Shannon prompt.
    Shannon bisa memilih salah satu, atau tetap generate sendiri.
    """
    if not tests:
        return ""

    lines = ["ATOMIC RED TEAM — BATTLE-TESTED PAYLOADS (tersedia lokal):"]
    for i, t in enumerate(tests, 1):
        elev = " [REQUIRES ELEVATION]" if t["elevation_required"] else ""
        lines.append(
            f"\n[ART-{i}] {t['name']}{elev}\n"
            f"  Platforms: {', '.join(t['platforms'])}\n"
            f"  Type: {t['task_type']}\n"
            f"  Command: {t['command'][:300]}"
        )
        if t["description"]:
            lines.append(f"  Info: {t['description'][:150]}")

    lines.append(
        "\nKamu BOLEH menggunakan salah satu ART payload di atas sebagai primary "
        "jika cocok dengan konteks target, atau buat sendiri jika ART tidak optimal."
    )
    return "\n".join(lines)
