"""
STIX 2.1 Mapper — Konversi konsep AEP ke objek STIX 2.1.

Mapping utama:
  ATT&CK Technique  → AttackPattern
  APT Profile       → ThreatActor + Identity
  Campaign          → Campaign (STIX)
  Finding (gap)     → Indicator + CourseOfAction
  Tactic string     → KillChainPhase

Semua objek di-cache per sesi mapper agar ID deterministik
(teknik yang sama menghasilkan STIX ID yang sama dalam satu bundle).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import stix2
from stix2 import (
    AttackPattern,
    Bundle,
    Campaign,
    CourseOfAction,
    Identity,
    Indicator,
    KillChainPhase,
    Relationship,
    ThreatActor,
)

# ─── Konstanta ────────────────────────────────────────────────────────────────

# Identity permanen untuk AEP sebagai "created_by"
AEP_IDENTITY = Identity(
    name="AE Platform",
    identity_class="system",
    description="AI-Powered Adversary Emulation Platform untuk ICS/OT + Enterprise IT",
)

# Mapping taktik AEP → nama Kill Chain MITRE ATT&CK
_TACTIC_MAP: dict[str, str] = {
    # Enterprise IT
    "initial_access":        "initial-access",
    "execution":             "execution",
    "persistence":           "persistence",
    "privilege_escalation":  "privilege-escalation",
    "defense_evasion":       "defense-evasion",
    "credential_access":     "credential-access",
    "discovery":             "discovery",
    "lateral_movement":      "lateral-movement",
    "collection":            "collection",
    "command_and_control":   "command-and-control",
    "exfiltration":          "exfiltration",
    "impact":                "impact",
    # ICS/OT (MITRE ATT&CK for ICS)
    "inhibit_response_function": "inhibit-response-function",
    "impair_process_control":    "impair-process-control",
    "evasion":                   "evasion",
    "reconnaissance":            "collection",       # ATT&CK ICS → collection alias
}

# Alias domain berdasarkan teknik ID prefix
def _domain_for_technique(technique_id: str) -> str:
    """enterprise-attack untuk T1xxx, ics-attack untuk T0xxx."""
    return "ics-attack" if technique_id.upper().startswith("T0") else "enterprise-attack"


# ─── Mapper Class ─────────────────────────────────────────────────────────────

class STIXMapper:
    """
    Stateful mapper yang men-cache objek STIX agar tidak duplikat dalam satu bundle.

    Penggunaan:
        mapper = STIXMapper()
        ap = mapper.technique_to_attack_pattern("T1566", "Phishing", "initial_access")
        bundle = mapper.build_bundle()
    """

    def __init__(self) -> None:
        self._bundle: dict[str, Any] = {}  # STIX id → STIX object (untuk build_bundle)
        self._cache: dict[str, Any] = {}   # cache_key → STIX object (untuk deduplication)
        # Selalu sertakan AEP identity
        self._add(AEP_IDENTITY)

    # ─── Public: Konverter ────────────────────────────────────────────────────

    def technique_to_attack_pattern(
        self,
        technique_id: str,
        technique_name: str | None = None,
        tactic: str | None = None,
        description: str | None = None,
    ) -> AttackPattern:
        """
        Konversi teknik ATT&CK ke STIX AttackPattern.
        Menggunakan deterministic ID via stix2.properties.
        Cache: teknik yang sama → objek yang sama.
        """
        cache_key = f"ap:{technique_id.upper()}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        kill_chain_phases = []
        if tactic:
            mapped = _TACTIC_MAP.get(tactic.lower(), tactic.lower().replace("_", "-"))
            kill_chain_phases.append(
                KillChainPhase(kill_chain_name="mitre-attack", phase_name=mapped)
            )

        ap = AttackPattern(
            name=technique_name or technique_id,
            description=description or f"ATT&CK Technique {technique_id}",
            external_references=[
                {
                    "source_name": "mitre-attack",
                    "external_id": technique_id.upper(),
                    "url": (
                        f"https://attack.mitre.org/techniques/{technique_id.upper().replace('.', '/')}/"
                    ),
                }
            ],
            kill_chain_phases=kill_chain_phases if kill_chain_phases else None,
            created_by_ref=AEP_IDENTITY.id,
        )
        self._add(ap)
        self._cache[cache_key] = ap
        return ap

    def apt_profile_to_threat_actor(
        self,
        profile_id: str,
        name: str,
        description: str | None = None,
        aliases: list[str] | None = None,
        sophistication: str = "advanced",
    ) -> tuple[ThreatActor, Identity]:
        """
        Konversi APT profile ke STIX ThreatActor + Identity (sebagai nama alias resmi).
        Mengembalikan tuple (ThreatActor, Identity).
        """
        cache_key = f"ta:{profile_id}"
        if cache_key in self._cache:
            return self._cache[cache_key], self._cache[f"id:{profile_id}"]

        actor_identity = Identity(
            name=name,
            identity_class="group",
            description=description or f"Threat actor group: {name}",
            created_by_ref=AEP_IDENTITY.id,
        )

        threat_actor = ThreatActor(
            name=name,
            description=description or f"Threat actor: {name}",
            aliases=aliases or [],
            sophistication=sophistication,
            created_by_ref=AEP_IDENTITY.id,
        )

        self._add(actor_identity)
        self._add(threat_actor)
        self._cache[cache_key] = threat_actor
        self._cache[f"id:{profile_id}"] = actor_identity
        return threat_actor, actor_identity

    def campaign_to_stix(
        self,
        campaign_id: str,
        name: str,
        description: str | None = None,
        first_seen: datetime | None = None,
        last_seen: datetime | None = None,
    ) -> Campaign:
        """Konversi kampanye AEP ke STIX Campaign object."""
        cache_key = f"camp:{campaign_id}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        kwargs: dict[str, Any] = {
            "name": name,
            "description": description or f"AEP Campaign: {name}",
            "created_by_ref": AEP_IDENTITY.id,
        }
        if first_seen:
            kwargs["first_seen"] = first_seen
        if last_seen:
            kwargs["last_seen"] = last_seen

        camp = Campaign(**kwargs)
        self._add(camp)
        self._cache[cache_key] = camp
        return camp

    def finding_to_indicator(
        self,
        technique_id: str,
        technique_name: str | None,
        sigma_rule: str | None = None,
        kql_query: str | None = None,
        severity: str = "medium",
    ) -> Indicator | None:
        """
        Konversi Finding (gap deteksi) ke STIX Indicator.
        Hanya dibuat jika ada sigma_rule atau kql_query sebagai basis pattern.
        Returns None jika tidak ada pattern yang tersedia.
        """
        if not sigma_rule and not kql_query:
            return None

        cache_key = f"ind:{technique_id.upper()}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # STIX pattern — gunakan generic network-traffic sebagai placeholder
        # karena sigma/KQL tidak memiliki ekuivalen langsung di STIX pattern language
        stix_pattern = (
            f"[network-traffic:dst_port > 0 AND "
            f"process:name MATCHES '{technique_id}']"
        )

        # Labels berdasarkan severity
        label_map = {
            "critical": "malicious-activity",
            "high":     "malicious-activity",
            "medium":   "suspicious-activity",
            "low":      "anomalous-activity",
        }
        labels = [label_map.get(severity, "suspicious-activity")]

        description_parts = [f"Detection gap for {technique_id}: {technique_name or technique_id}."]
        if sigma_rule:
            description_parts.append(f"\n\nSigma Rule Hint:\n{sigma_rule}")
        if kql_query:
            description_parts.append(f"\n\nKQL Query:\n{kql_query}")

        ind = Indicator(
            name=f"Detection Gap: {technique_id}",
            description="\n".join(description_parts),
            pattern=stix_pattern,
            pattern_type="stix",
            indicator_types=labels,
            valid_from=datetime.now(timezone.utc),
            created_by_ref=AEP_IDENTITY.id,
            labels=labels,
        )
        self._add(ind)
        self._cache[cache_key] = ind
        return ind

    def remediation_to_course_of_action(
        self,
        technique_id: str,
        remediation: str,
    ) -> CourseOfAction:
        """Konversi rekomendasi remediation ke STIX CourseOfAction."""
        cache_key = f"coa:{technique_id.upper()}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        coa = CourseOfAction(
            name=f"Remediation: {technique_id}",
            description=remediation,
            created_by_ref=AEP_IDENTITY.id,
        )
        self._add(coa)
        self._cache[cache_key] = coa
        return coa

    def add_relationship(
        self,
        source: Any,
        relationship_type: str,
        target: Any,
        description: str | None = None,
    ) -> Relationship:
        """Tambah relasi antar objek STIX."""
        kwargs: dict[str, Any] = {
            "relationship_type": relationship_type,
            "source_ref": source.id,
            "target_ref": target.id,
            "created_by_ref": AEP_IDENTITY.id,
        }
        if description:
            kwargs["description"] = description

        rel = Relationship(**kwargs)
        self._add(rel)
        return rel

    # ─── Build Bundle ─────────────────────────────────────────────────────────

    def build_bundle(self) -> Bundle:
        """Kumpulkan semua objek yang sudah di-add dan kembalikan sebagai STIX Bundle."""
        return Bundle(objects=list(self._bundle.values()), allow_custom=True)

    def to_json(self, indent: int = 2) -> str:
        """Serialisasi bundle ke JSON string."""
        return self.build_bundle().serialize(pretty=True)

    # ─── Internal ─────────────────────────────────────────────────────────────

    def _add(self, obj: Any) -> None:
        """Tambah objek ke bundle registry dengan STIX ID sebagai key."""
        self._bundle[obj.id] = obj

    @property
    def object_count(self) -> int:
        return len(self._bundle)
