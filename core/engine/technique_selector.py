"""
Technique Selector — Logika pemilihan teknik yang optimal untuk setiap langkah kampanye.

Selector bekerja sebagai lapisan antara AI Decision Engine dan Technique Registry.
Tugasnya menyempurnakan daftar kandidat teknik berdasarkan:
- Fase ATT&CK saat ini (taktik)
- Lingkungan target (IT vs OT)
- Profil APT yang disimulasikan
- Level risiko yang diizinkan
- Hasil langkah sebelumnya (adaptive selection)
"""

from dataclasses import dataclass, field
from typing import Any

from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.models.technique import Technique
from core.techniques.registry import TechniqueRegistry


# ─── ATT&CK Tactic Kill Chain Sequence ───────────────────────────────────────
# Urutan logis taktik ATT&CK Enterprise
IT_TACTIC_SEQUENCE = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

# Urutan taktik ICS ATT&CK
OT_TACTIC_SEQUENCE = [
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "evasion",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "inhibit-response-function",
    "impair-process-control",
    "impact",
]

# Mapping taktik → teknik yang umum dipakai
TACTIC_PREFERRED_TECHNIQUES: dict[str, list[str]] = {
    "initial-access":        ["T1566", "T1190", "T1078", "T1133"],
    "execution":             ["T1059", "T1106", "T1203", "T1569"],
    "persistence":           ["T1078", "T1547", "T1543", "T1053"],
    "privilege-escalation":  ["T1078", "T1055", "T1134", "T1548"],
    "defense-evasion":       ["T1027", "T1036", "T1070", "T1562"],
    "credential-access":     ["T1003", "T1558", "T1110", "T1552"],
    "discovery":             ["T1082", "T1083", "T1049", "T1135"],
    "lateral-movement":      ["T1021", "T1550", "T1534", "T1570"],
    "collection":            ["T1005", "T1039", "T1074", "T1560"],
    "command-and-control":   ["T1071", "T1095", "T1090", "T1573"],
    "exfiltration":          ["T1041", "T1048", "T1567", "T1052"],
    "impact":                ["T1486", "T1490", "T1498", "T1565"],
    # OT tactics
    "inhibit-response-function": ["T0816", "T0826", "T0835", "T0838"],
    "impair-process-control":    ["T0806", "T0831", "T0836", "T0855"],
}


@dataclass
class TechniqueCandidate:
    """Teknik kandidat dengan skor dan alasan pemilihan."""
    technique_id: str
    name: str
    tactic: str
    environment: str
    risk_level: str
    score: float                      # 0.0 - 1.0 semakin tinggi semakin baik
    score_breakdown: dict[str, float] = field(default_factory=dict)
    is_registered: bool = False       # Apakah ada implementasi konkret di registry
    metadata: dict[str, Any] = field(default_factory=dict)


class TechniqueSelector:
    """
    Pemilih teknik yang optimal berdasarkan konteks kampanye.

    Algoritma scoring:
    - +0.30 jika teknik sudah di-implementasikan di registry
    - +0.25 jika teknik sesuai preferensi APT yang disimulasikan
    - +0.20 berdasarkan kesesuaian taktik dengan fase saat ini
    - +0.15 berdasarkan level risiko (lower risk = higher score untuk stealth)
    - +0.10 berdasarkan lingkungan target yang tepat
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.registry = TechniqueRegistry.instance()

    async def get_candidates(
        self,
        tactic: str,
        environment: str,
        apt_preferred_ids: list[str] | None = None,
        max_risk: str = "high",
        limit: int = 20,
        exclude_ids: list[str] | None = None,
    ) -> list[TechniqueCandidate]:
        """
        Dapatkan daftar teknik kandidat yang disortir berdasarkan skor relevansi.

        Args:
            tactic:           Taktik ATT&CK yang sedang dieksekusi
            environment:      'it', 'ot', atau 'hybrid'
            apt_preferred_ids: ID teknik yang disukai oleh APT yang disimulasikan
            max_risk:         Level risiko maksimum yang diizinkan
            limit:            Jumlah maksimum kandidat yang dikembalikan
            exclude_ids:      Teknik yang sudah dieksekusi (hindari duplikasi)
        """
        apt_preferred_ids = apt_preferred_ids or []
        exclude_ids = set(exclude_ids or [])

        # ─── Ambil teknik dari database ───────────────────────────────────────
        env_filter = ["it", "both"] if environment == "it" else ["ot", "both"]
        risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        max_risk_val = risk_order.get(max_risk, 2)

        result = await self.session.execute(
            select(Technique).where(
                Technique.tactic == tactic,
                Technique.environment.in_(env_filter),
            )
        )
        db_techniques = result.scalars().all()

        # ─── Scoring setiap kandidat ───────────────────────────────────────────
        candidates = []
        registered_ids = set(self.registry.list_all())
        preferred_in_tactic = TACTIC_PREFERRED_TECHNIQUES.get(tactic, [])

        for tech in db_techniques:
            if tech.id in exclude_ids:
                continue
            if risk_order.get(tech.risk_level, 0) > max_risk_val:
                continue

            score = 0.0
            breakdown: dict[str, float] = {}

            # +0.30 implementasi konkret tersedia
            if tech.id in registered_ids:
                score += 0.30
                breakdown["registered"] = 0.30

            # +0.25 disukai APT
            if tech.id in apt_preferred_ids:
                score += 0.25
                breakdown["apt_preferred"] = 0.25

            # +0.20 direkomendasikan untuk taktik ini
            if tech.id in preferred_in_tactic:
                score += 0.20
                breakdown["tactic_preferred"] = 0.20

            # +0.15 risk-adjusted (lower risk = lebih aman, dapat nilai lebih tinggi)
            risk_score = {
                "low": 0.15, "medium": 0.10, "high": 0.05, "critical": 0.0
            }.get(tech.risk_level, 0.05)
            score += risk_score
            breakdown["risk_adjusted"] = risk_score

            # +0.10 lingkungan target yang tepat (exact match lebih baik dari "both")
            if (environment == "it" and tech.environment == "it") or \
               (environment == "ot" and tech.environment == "ot"):
                score += 0.10
                breakdown["env_exact"] = 0.10

            candidates.append(TechniqueCandidate(
                technique_id=tech.id,
                name=tech.name,
                tactic=tech.tactic,
                environment=tech.environment,
                risk_level=tech.risk_level,
                score=round(score, 3),
                score_breakdown=breakdown,
                is_registered=tech.id in registered_ids,
                metadata={
                    "detection_note": tech.detection_note[:200] if tech.detection_note else "",
                    "platforms": tech.platforms,
                    "destructive": tech.destructive,
                },
            ))

        # Sortir berdasarkan skor descending, ambil limit teratas
        candidates.sort(key=lambda c: c.score, reverse=True)
        return candidates[:limit]

    async def suggest_attack_chain(
        self,
        environment: str,
        objectives: list[str],
        apt_preferred_ids: list[str] | None = None,
        max_risk: str = "high",
    ) -> list[dict]:
        """
        Sarankan rantai serangan lengkap berdasarkan tujuan kampanye.
        Mengembalikan urutan langkah yang direkomendasikan dari initial access → impact.

        Args:
            environment:  'it', 'ot', atau 'hybrid'
            objectives:   Tujuan kampanye (misal: ["lateral_movement", "data_exfiltration"])
            apt_preferred_ids: ID teknik preferensi APT
            max_risk:     Level risiko maksimum
        """
        tactic_sequence = OT_TACTIC_SEQUENCE if environment == "ot" else IT_TACTIC_SEQUENCE

        # Filter taktik berdasarkan objectives
        relevant_tactics = self._filter_tactics_by_objectives(tactic_sequence, objectives)

        chain = []
        for tactic in relevant_tactics:
            candidates = await self.get_candidates(
                tactic=tactic,
                environment=environment,
                apt_preferred_ids=apt_preferred_ids,
                max_risk=max_risk,
                limit=3,
            )
            if candidates:
                best = candidates[0]
                chain.append({
                    "phase": tactic,
                    "technique_id": best.technique_id,
                    "technique_name": best.name,
                    "score": best.score,
                    "is_implemented": best.is_registered,
                    "risk_level": best.risk_level,
                    "alternatives": [
                        {"id": c.technique_id, "name": c.name}
                        for c in candidates[1:3]
                    ],
                })

        return chain

    def _filter_tactics_by_objectives(
        self, tactic_sequence: list[str], objectives: list[str]
    ) -> list[str]:
        """Pilih taktik yang relevan berdasarkan objectives kampanye."""
        objective_tactic_map = {
            "initial_access":       ["initial-access"],
            "gain_initial_access":  ["initial-access"],
            "execution":            ["execution"],
            "persistence":          ["persistence"],
            "privilege_escalation": ["privilege-escalation"],
            "lateral_movement":     ["discovery", "lateral-movement"],
            "credential_theft":     ["credential-access"],
            "data_collection":      ["collection"],
            "data_exfiltration":    ["collection", "exfiltration"],
            "c2_establishment":     ["command-and-control"],
            "impact":               ["impact"],
            "ics_manipulation":     ["inhibit-response-function", "impair-process-control"],
            "full_chain":           tactic_sequence,
        }

        relevant = set()
        # Selalu mulai dari initial access
        relevant.add("initial-access")
        relevant.add("execution")

        for obj in objectives:
            obj_normalized = obj.lower().replace(" ", "_").replace("-", "_")
            tactics = objective_tactic_map.get(obj_normalized, [])
            relevant.update(tactics)

        # Pertahankan urutan kill chain
        return [t for t in tactic_sequence if t in relevant]

    async def get_fallback_technique(
        self,
        failed_technique_id: str,
        tactic: str,
        environment: str,
    ) -> str | None:
        """
        Cari teknik fallback setelah teknik utama gagal.
        Pilih teknik berbeda dengan tujuan yang sama tapi pendekatan berbeda.
        """
        candidates = await self.get_candidates(
            tactic=tactic,
            environment=environment,
            limit=10,
            exclude_ids=[failed_technique_id],
        )
        if candidates:
            return candidates[0].technique_id
        return None
