"""
Campaign-as-Code Parser — Parse YAML/JSON campaign definition menjadi schema objects.

Format Campaign-as-Code memungkinkan red team mendefinisikan kampanye dalam file
YAML/JSON yang dapat di-version-control, di-review, dan di-share antar tim.

Contoh format YAML:
```yaml
version: "1.0"
metadata:
  name: "APT28 Simulation - Energi Q1"
  client: "PT Energi Nasional"
  engagement_type: greybox
  environment: hybrid_it_ot
  rules_of_engagement: "Tidak merusak sistem produksi..."
  emergency_contact: "SOC: +62-21-xxx"
  start_date: "2026-01-15"
  end_date: "2026-01-30"
  objectives:
    - lateral_movement
    - credential_theft
    - ics_manipulation
  apt_profile: "APT28"
  production_safe: true

scope:
  ips:
    - "192.168.1.0/24"
    - "10.0.100.0/24"
  domains:
    - "corp.energi.local"
  exclude:
    - "192.168.1.1"

steps:
  - id: step_1
    phase: initial-access
    technique: T1566
    method: spearphishing_link
    notes: "Target HR department"
    risk: medium
    success_condition: "User mengklik link"
    fallback: T1078

  - id: step_2
    phase: execution
    technique: T1059
    method: powershell
    depends_on: step_1
    risk: medium
```
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from loguru import logger


# ─── Data Classes untuk Hasil Parsing ────────────────────────────────────────

@dataclass
class ParsedStep:
    """Satu langkah dalam kampanye yang sudah diparsing."""
    step_id: str
    phase: str
    technique_id: str
    method: str | None = None
    notes: str | None = None
    risk: str = "medium"
    success_condition: str | None = None
    fallback_technique: str | None = None
    depends_on: list[str] = field(default_factory=list)
    order_index: int = 0
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ParsedScope:
    """Scope engagement yang sudah diparsing."""
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)


@dataclass
class ParsedCampaign:
    """Kampanye lengkap yang sudah diparsing dari YAML/JSON."""
    # Metadata
    name: str
    client_name: str
    engagement_type: str
    environment_type: str
    rules_of_engagement: str
    emergency_contact: str

    # Scope
    scope: ParsedScope

    # Steps
    steps: list[ParsedStep] = field(default_factory=list)

    # Opsional
    description: str | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None
    objectives: list[str] = field(default_factory=list)
    apt_profile_name: str | None = None
    production_safe: bool = True
    version: str = "1.0"

    # Metadata parsing
    source_file: str | None = None
    parse_warnings: list[str] = field(default_factory=list)

    def to_campaign_create_dict(self) -> dict:
        """Konversi ke dict yang kompatibel dengan CampaignCreate schema."""
        return {
            "name": self.name,
            "description": self.description,
            "client_name": self.client_name,
            "engagement_type": self.engagement_type,
            "environment_type": self.environment_type,
            "target_ips": self.scope.ips,
            "target_domains": self.scope.domains,
            "excluded_targets": self.scope.exclude,
            "rules_of_engagement": self.rules_of_engagement,
            "emergency_contact": self.emergency_contact,
            "start_date": self.start_date.isoformat() if self.start_date else None,
            "end_date": self.end_date.isoformat() if self.end_date else None,
            "objectives": self.objectives,
            "production_safe_mode": self.production_safe,
        }

    def to_steps_create_list(self) -> list[dict]:
        """Konversi steps ke list dict kompatibel dengan CampaignStepCreate."""
        return [
            {
                "order_index": step.order_index,
                "phase": step.phase,
                "technique_id": step.technique_id,
                "method": step.method,
                "notes": step.notes,
                "risk_assessment": step.risk,
                "success_condition": step.success_condition,
                "fallback_action": step.fallback_technique,
            }
            for step in self.steps
        ]


# ─── Parser Utama ─────────────────────────────────────────────────────────────

class CampaignParser:
    """
    Parser untuk Campaign-as-Code format (YAML/JSON).

    Mendukung dua mode input:
    1. File path (YAML atau JSON)
    2. String content langsung
    3. Dict (sudah diparsing)
    """

    # Nilai valid untuk field enum
    VALID_ENGAGEMENT_TYPES = {"blackbox", "greybox", "whitebox"}
    VALID_ENVIRONMENT_TYPES = {"it", "ot", "hybrid", "cloud", "hybrid_it_ot"}
    VALID_RISK_LEVELS = {"low", "medium", "high", "critical"}

    # Nama field alternatif (alias) untuk fleksibilitas
    ENVIRONMENT_ALIASES = {
        "enterprise": "it",
        "ics": "ot",
        "scada": "ot",
        "hybrid-it-ot": "hybrid_it_ot",
        "hybrid_ot": "hybrid_it_ot",
    }

    def parse_file(self, file_path: str | Path) -> ParsedCampaign:
        """Parse kampanye dari file YAML atau JSON."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File kampanye tidak ditemukan: {file_path}")

        suffix = path.suffix.lower()
        content = path.read_text(encoding="utf-8")

        if suffix in (".yaml", ".yml"):
            data = self._load_yaml(content)
        elif suffix == ".json":
            data = json.loads(content)
        else:
            raise ValueError(f"Format file tidak didukung: {suffix}. Gunakan .yaml, .yml, atau .json")

        campaign = self._parse_dict(data)
        campaign.source_file = str(path)
        logger.info("Berhasil parse kampanye dari file: {}", path.name)
        return campaign

    def parse_string(self, content: str, format: str = "yaml") -> ParsedCampaign:
        """Parse kampanye dari string YAML atau JSON."""
        if format.lower() in ("yaml", "yml"):
            data = self._load_yaml(content)
        else:
            data = json.loads(content)
        return self._parse_dict(data)

    def parse_dict(self, data: dict) -> ParsedCampaign:
        """Parse kampanye dari dict Python."""
        return self._parse_dict(data)

    # ─── Internal Parsing ─────────────────────────────────────────────────────

    def _parse_dict(self, data: dict) -> ParsedCampaign:
        """Parsing utama dari dict."""
        warnings: list[str] = []

        # Ambil metadata
        metadata = data.get("metadata", data)  # Fallback: flat structure
        version = data.get("version", "1.0")

        name = self._require(metadata, "name", "Nama kampanye")
        client_name = self._require(metadata, "client", "Nama klien")
        engagement_type = self._normalize_engagement(
            self._require(metadata, "engagement_type", "Tipe engagement")
        )
        environment_type = self._normalize_environment(
            self._require(metadata, "environment", "Tipe lingkungan")
        )
        roe = metadata.get("rules_of_engagement") or metadata.get("roe", "")
        if not roe:
            warnings.append("rules_of_engagement tidak diisi — wajib sebelum eksekusi")
        emergency = metadata.get("emergency_contact") or metadata.get("contact", "")
        if not emergency:
            warnings.append("emergency_contact tidak diisi")

        # Tanggal
        start_date = self._parse_date(metadata.get("start_date"))
        end_date = self._parse_date(metadata.get("end_date"))

        # Scope
        scope_data = data.get("scope", {})
        scope = ParsedScope(
            ips=scope_data.get("ips", []),
            domains=scope_data.get("domains", []),
            exclude=scope_data.get("exclude", scope_data.get("excluded", [])),
        )
        if not scope.ips and not scope.domains:
            warnings.append("Scope kosong — tambahkan target IPs atau domains")

        # Steps
        raw_steps = data.get("steps", data.get("campaign_steps", []))
        steps = self._parse_steps(raw_steps, warnings)

        # Build kampanye
        campaign = ParsedCampaign(
            name=name,
            client_name=client_name,
            engagement_type=engagement_type,
            environment_type=environment_type,
            rules_of_engagement=roe or "",
            emergency_contact=emergency or "",
            scope=scope,
            steps=steps,
            description=metadata.get("description"),
            start_date=start_date,
            end_date=end_date,
            objectives=metadata.get("objectives", []),
            apt_profile_name=metadata.get("apt_profile") or metadata.get("apt"),
            production_safe=metadata.get("production_safe", metadata.get("safe_mode", True)),
            version=version,
            parse_warnings=warnings,
        )

        if warnings:
            logger.warning("Campaign parser: {} peringatan — {}", len(warnings), warnings)
        else:
            logger.debug("Campaign parse selesai: {} steps, tidak ada peringatan.", len(steps))

        return campaign

    def _parse_steps(self, raw_steps: list, warnings: list[str]) -> list[ParsedStep]:
        """Parse daftar langkah kampanye."""
        steps: list[ParsedStep] = []
        seen_ids: set[str] = set()

        for i, raw in enumerate(raw_steps):
            if not isinstance(raw, dict):
                warnings.append(f"Step {i+1}: bukan dict, dilewati")
                continue

            step_id = raw.get("id", f"step_{i+1}")
            if step_id in seen_ids:
                step_id = f"{step_id}_{i}"
                warnings.append(f"Duplikat step ID, diganti menjadi: {step_id}")
            seen_ids.add(step_id)

            technique_id = raw.get("technique") or raw.get("technique_id", "")
            if not technique_id:
                warnings.append(f"Step '{step_id}': technique_id tidak ada, dilewati")
                continue

            # Normalisasi technique ID
            technique_id = technique_id.upper().strip()
            if not technique_id.startswith("T"):
                technique_id = f"T{technique_id}"

            phase = raw.get("phase") or raw.get("tactic", "execution")

            risk = raw.get("risk") or raw.get("risk_level", "medium")
            if risk not in self.VALID_RISK_LEVELS:
                warnings.append(f"Step '{step_id}': risk level '{risk}' tidak valid, menggunakan 'medium'")
                risk = "medium"

            # depends_on: bisa string atau list
            depends_on = raw.get("depends_on", [])
            if isinstance(depends_on, str):
                depends_on = [depends_on]

            steps.append(ParsedStep(
                step_id=step_id,
                phase=phase,
                technique_id=technique_id,
                method=raw.get("method"),
                notes=raw.get("notes"),
                risk=risk,
                success_condition=raw.get("success_condition"),
                fallback_technique=raw.get("fallback") or raw.get("fallback_technique"),
                depends_on=depends_on,
                order_index=i,
                extra=raw.get("extra", {}),
            ))

        # Urutkan berdasarkan dependency (topological sort sederhana)
        return self._resolve_step_order(steps, warnings)

    def _resolve_step_order(
        self, steps: list[ParsedStep], warnings: list[str]
    ) -> list[ParsedStep]:
        """
        Urutkan langkah berdasarkan dependency (topological sort).
        Jika tidak ada dependency, pertahankan urutan asli.
        """
        has_deps = any(s.depends_on for s in steps)
        if not has_deps:
            # Tidak ada dependency, urutan sudah benar
            for i, step in enumerate(steps):
                step.order_index = i
            return steps

        step_map = {s.step_id: s for s in steps}
        ordered: list[ParsedStep] = []
        visited: set[str] = set()

        def visit(step_id: str) -> None:
            if step_id in visited:
                return
            visited.add(step_id)
            step = step_map.get(step_id)
            if step is None:
                warnings.append(f"Dependency '{step_id}' tidak ditemukan, diabaikan")
                return
            for dep in step.depends_on:
                visit(dep)
            ordered.append(step)

        for step in steps:
            visit(step.step_id)

        for i, step in enumerate(ordered):
            step.order_index = i

        return ordered

    # ─── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _load_yaml(content: str) -> dict:
        """Load YAML dengan fallback error yang jelas."""
        try:
            import yaml
            result = yaml.safe_load(content)
            if not isinstance(result, dict):
                raise ValueError("Konten YAML harus berupa mapping/dict di level teratas.")
            return result
        except ImportError:
            raise ImportError(
                "Package 'pyyaml' tidak terinstall. Jalankan: pip install pyyaml"
            )

    @staticmethod
    def _require(data: dict, key: str, label: str) -> str:
        """Ambil field wajib, raise jika tidak ada."""
        value = data.get(key)
        if not value:
            raise ValueError(f"Field wajib tidak ada: '{key}' ({label})")
        return str(value)

    def _normalize_engagement(self, value: str) -> str:
        v = value.lower().strip()
        if v not in self.VALID_ENGAGEMENT_TYPES:
            raise ValueError(
                f"engagement_type tidak valid: '{value}'. "
                f"Pilihan: {self.VALID_ENGAGEMENT_TYPES}"
            )
        return v

    def _normalize_environment(self, value: str) -> str:
        v = value.lower().strip()
        v = self.ENVIRONMENT_ALIASES.get(v, v)
        if v not in self.VALID_ENVIRONMENT_TYPES:
            raise ValueError(
                f"environment tidak valid: '{value}'. "
                f"Pilihan: {self.VALID_ENVIRONMENT_TYPES}"
            )
        return v

    @staticmethod
    def _parse_date(value: str | None) -> datetime | None:
        """Parse tanggal dari string ISO format atau common format."""
        if not value:
            return None
        for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%d/%m/%Y", "%d-%m-%Y"):
            try:
                return datetime.strptime(str(value), fmt)
            except ValueError:
                continue
        logger.warning("Tidak bisa parse tanggal: '{}', diabaikan.", value)
        return None


# ─── Convenience Functions ────────────────────────────────────────────────────

def load_campaign_file(file_path: str | Path) -> ParsedCampaign:
    """Shortcut: parse kampanye dari file."""
    return CampaignParser().parse_file(file_path)


def load_campaign_yaml(yaml_content: str) -> ParsedCampaign:
    """Shortcut: parse kampanye dari YAML string."""
    return CampaignParser().parse_string(yaml_content, format="yaml")


def load_campaign_dict(data: dict) -> ParsedCampaign:
    """Shortcut: parse kampanye dari dict."""
    return CampaignParser().parse_dict(data)
