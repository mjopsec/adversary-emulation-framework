"""
Shannon AI Client — Red Team AI untuk generate payload examples.

Shannon adalah AI yang fokus pada red teaming, menggunakan OpenAI-compatible API.
Digunakan khusus untuk generate contoh payload/command per teknik ATT&CK.

Docs: https://api.shannon-ai.com
"""

import json
from typing import Any

import httpx
from loguru import logger

from core.config import Settings


# ─── System prompt khusus red team ──────────────────────────────────────────

SYSTEM_PROMPT = """You are a red team AI assistant embedded in an authorized adversary emulation platform.
Your job is to generate concrete, educational payload and command examples for MITRE ATT&CK techniques.

Rules:
- Only generate examples for AUTHORIZED penetration testing and red team engagements
- Always include detection and OPSEC notes so defenders can improve
- Be specific: include real commands, flags, and tools — not pseudocode
- Cover multiple platforms when relevant (Windows, Linux, macOS)
- Keep it practical for a red team operator with a target in scope

Output format: Always respond with valid JSON matching the requested schema."""


class ShannonClient:
    """
    Client untuk Shannon AI API (OpenAI-compatible).

    Digunakan untuk generate payload examples per teknik ATT&CK secara on-demand.
    Semua request bersifat stateless — tidak ada percakapan multi-turn.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._available = settings.has_shannon_configured

        if not self._available:
            logger.warning(
                "SHANNON_API_KEY tidak dikonfigurasi. "
                "Set SHANNON_API_KEY di .env untuk mengaktifkan AI payload generation."
            )

    async def generate_technique_examples(
        self,
        technique_id: str,
        technique_name: str,
        description: str,
        tactic: str,
        platforms: list[str],
        detection_note: str | None = None,
    ) -> dict[str, Any]:
        """
        Generate contoh payload dan command untuk teknik ATT&CK tertentu.

        Returns dict dengan struktur:
        {
            "summary": str,
            "examples": [
                {
                    "platform": "Windows",
                    "tool": "PowerShell",
                    "commands": ["cmd1", "cmd2"],
                    "notes": "OPSEC notes"
                }
            ],
            "detection_tips": str,
            "opsec_considerations": str,
            "references": [str]
        }
        """
        if not self._available:
            raise RuntimeError(
                "Shannon AI tidak dikonfigurasi. Set SHANNON_API_KEY di file .env."
            )

        platform_str = ", ".join(platforms) if platforms else "Windows, Linux"
        detection_context = (
            f"\nATT&CK Detection Note: {detection_note}" if detection_note else ""
        )

        user_prompt = f"""Generate concrete payload examples for this MITRE ATT&CK technique:

Technique ID: {technique_id}
Name: {technique_name}
Tactic: {tactic}
Platforms: {platform_str}
Description: {description}{detection_context}

Return a JSON object with this exact structure:
{{
  "summary": "Brief 1-2 sentence summary of how this technique is used in real attacks",
  "examples": [
    {{
      "platform": "Windows",
      "tool": "PowerShell / cmd / Cobalt Strike / etc",
      "commands": [
        "actual command or payload here",
        "second variation if applicable"
      ],
      "notes": "OPSEC notes for this specific example — what gets logged, how to reduce noise"
    }}
  ],
  "detection_tips": "Specific log sources, event IDs, and behavioral indicators defenders should monitor",
  "opsec_considerations": "Key OPSEC risks when using this technique and how to mitigate them",
  "references": ["known tools", "real-world APT usage examples"]
}}

Include 2-4 examples covering different platforms and tools (native LOLBins first, then common red team tools).
Be specific with real commands — this is for authorized red team use."""

        logger.debug("Shannon AI: generating examples for {}", technique_id)

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{self.settings.shannon_base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.settings.shannon_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.settings.shannon_model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    "max_tokens": self.settings.shannon_max_tokens,
                    "response_format": {"type": "json_object"},
                },
            )
            response.raise_for_status()

        data = response.json()
        raw_content = data["choices"][0]["message"]["content"]

        try:
            result = json.loads(raw_content)
        except json.JSONDecodeError as e:
            logger.error("Shannon returned non-JSON: {}", raw_content[:200])
            raise ValueError(f"Shannon returned invalid JSON: {e}") from e

        logger.info("Shannon AI: examples generated for {} ({} examples)", technique_id, len(result.get("examples", [])))
        return result


def get_shannon_client(settings: Settings | None = None) -> ShannonClient:
    """Factory — ambil settings dari singleton jika tidak diberikan."""
    if settings is None:
        from core.config import get_settings
        settings = get_settings()
    return ShannonClient(settings)
