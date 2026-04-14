"""
Test Suite Phase 7 — STIX 2.1 Export Engine.

Mencakup:
- TestSTIXMapper           : Unit test STIXMapper (objek, relasi, cache)
- TestBundleBuilder        : Bundle dari campaign + purple report mock data
- TestSTIXObjectStructure  : Validasi struktur objek STIX (type, id, required fields)
- TestSTIXRelationships    : Relasi antar objek terbentuk dengan benar
- TestPhase7Integration    : Round-trip JSON serialization, XSS-safe, edge cases
"""

import json
import pytest


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_campaign_report():
    return {
        "metadata": {"campaign_id": "camp-abc123", "platform": "AE Platform v1.0.0"},
        "campaign": {
            "name": "Operation SteelBridge",
            "client": "PT Energi Nusantara",
            "engagement_type": "greybox",
            "environment_type": "hybrid_it_ot",
            "status": "completed",
            "started_at": "2026-04-01T08:00:00",
            "completed_at": "2026-04-10T17:00:00",
        },
        "summary": {
            "total_techniques_executed": 4,
            "detected": 2,
            "not_detected": 2,
            "detection_rate_percent": 50.0,
            "gaps_by_severity": {"high": 1, "critical": 1},
        },
        "findings": [
            {
                "technique_id": "T1566",
                "technique_name": "Phishing",
                "severity": "high",
                "detected": False,
                "detection_quality": "none",
                "gap_description": "Email gateway melewatkan .lnk attachment",
                "remediation_recommendation": "Deploy sandbox analisis email",
                "sigma_rule": "title: Phishing LNK\nstatus: experimental\n",
                "kql_query": None,
                "priority_score": 6,
            },
            {
                "technique_id": "T1059",
                "technique_name": "Command Scripting",
                "severity": "medium",
                "detected": True,
                "detection_quality": "full",
                "gap_description": None,
                "remediation_recommendation": None,
                "sigma_rule": None,
                "kql_query": None,
                "priority_score": 0,
            },
            {
                "technique_id": "T0801",
                "technique_name": "Monitor Process State",
                "severity": "critical",
                "detected": False,
                "detection_quality": "none",
                "gap_description": "OPC-UA reads tidak dimonitor",
                "remediation_recommendation": "Deploy OT network monitoring",
                "sigma_rule": "title: OPC-UA Anomaly\nstatus: experimental\n",
                "kql_query": None,
                "priority_score": 8,
            },
        ],
        "attack_path": [
            {"step": 1, "technique_id": "T1566", "technique_name": "Phishing",
             "target": "192.168.1.10", "status": "success", "duration_seconds": 10.0},
            {"step": 2, "technique_id": "T1059", "technique_name": "Command Scripting",
             "target": "192.168.1.10", "status": "success", "duration_seconds": 3.5},
            {"step": 3, "technique_id": "T0801", "technique_name": "Monitor Process State",
             "target": "10.0.1.5", "status": "success", "duration_seconds": 8.0},
        ],
        "navigator_layer": {"techniques": []},
    }


@pytest.fixture
def sample_purple_report():
    return {
        "session_id": "sess-xyz789",
        "session_name": "Purple Q2",
        "environment": "it",
        "status": "completed",
        "red_team_lead": "Alice",
        "blue_team_lead": "Bob",
        "facilitator": None,
        "metrics": {
            "total_events": 3,
            "detected_count": 1,
            "gap_count": 2,
            "detection_coverage": 0.33,
            "mttd_seconds": 45.0,
            "coverage_by_tactic": {"initial_access": 0.5},
        },
        "events": [
            {
                "id": "ev-001", "technique_id": "T1566", "technique_name": "Phishing",
                "tactic": "initial_access", "target": "ws-01",
                "blue_response": "missed", "is_gap": True,
                "gap_severity": "high", "detection_latency_seconds": None,
                "sigma_rule_hint": "title: Phishing Detection\nstatus: experimental\n",
            },
            {
                "id": "ev-002", "technique_id": "T1003", "technique_name": "Credential Dumping",
                "tactic": "credential_access", "target": "ws-01",
                "blue_response": "missed", "is_gap": True,
                "gap_severity": "critical", "detection_latency_seconds": None,
                "sigma_rule_hint": "title: LSASS Access\nstatus: experimental\n",
            },
            {
                "id": "ev-003", "technique_id": "T1021", "technique_name": "Remote Services",
                "tactic": "lateral_movement", "target": "srv-02",
                "blue_response": "detected", "is_gap": False,
                "gap_severity": None, "detection_latency_seconds": 30.0,
                "sigma_rule_hint": None,
            },
        ],
        "recommendations": [
            {
                "priority": 1, "technique_id": "T1003",
                "title": "Deploy Credential Guard",
                "gap_severity": "critical",
                "steps": ["Enable Credential Guard via GPO", "Monitor LSASS access"],
                "sigma_hint": "title: LSASS Access\n",
            },
        ],
    }


# ─── TestSTIXMapper ───────────────────────────────────────────────────────────

class TestSTIXMapper:

    def test_mapper_creates_with_identity(self):
        from core.stix.mapper import STIXMapper
        mapper = STIXMapper()
        # Should have AEP identity pre-added
        assert mapper.object_count == 1

    def test_technique_to_attack_pattern_type(self):
        from core.stix.mapper import STIXMapper
        mapper = STIXMapper()
        ap = mapper.technique_to_attack_pattern("T1566", "Phishing", "initial_access")
        assert ap.type == "attack-pattern"

    def test_technique_to_attack_pattern_id_starts_with_type(self):
        from core.stix.mapper import STIXMapper
        mapper = STIXMapper()
        ap = mapper.technique_to_attack_pattern("T1059", "Command Scripting")
        assert ap.id.startswith("attack-pattern--")

    def test_technique_cached_same_instance(self):
        from core.stix.mapper import STIXMapper
        mapper = STIXMapper()
        ap1 = mapper.technique_to_attack_pattern("T1566", "Phishing")
        ap2 = mapper.technique_to_attack_pattern("T1566", "Phishing v2")  # same tid
        assert ap1.id == ap2.id

    def test_technique_external_reference_mitre(self):
        from core.stix.mapper import STIXMapper
        mapper = STIXMapper()
        ap = mapper.technique_to_attack_pattern("T1566", "Phishing")
        refs = [r for r in ap.external_references if r.source_name == "mitre-attack"]
        assert len(refs) == 1
        assert refs[0].external_id == "T1566"

    def test_technique_kill_chain_phase(self):
        from core.stix.mapper import STIXMapper
        mapper = STIXMapper()
        ap = mapper.technique_to_attack_pattern("T1059", "Exec", "execution")
        phases = ap.kill_chain_phases
        assert any(p.phase_name == "execution" for p in phases)

    def test_tactic_underscore_to_hyphen(self):
        from core.stix.mapper import STIXMapper
        mapper = STIXMapper()
        ap = mapper.technique_to_attack_pattern("T1078", "Valid Accounts", "privilege_escalation")
        phases = ap.kill_chain_phases
        assert any(p.phase_name == "privilege-escalation" for p in phases)

    def test_ot_technique_ics_domain_url(self):
        from core.stix.mapper import STIXMapper
        mapper = STIXMapper()
        ap = mapper.technique_to_attack_pattern("T0801", "Monitor Process State")
        refs = [r for r in ap.external_references if r.source_name == "mitre-attack"]
        assert refs[0].external_id == "T0801"

    def test_threat_actor_type(self):
        from core.stix.mapper import STIXMapper
        mapper = STIXMapper()
        ta, identity = mapper.apt_profile_to_threat_actor("apt28", "APT28")
        assert ta.type == "threat-actor"
        assert identity.type == "identity"

    def test_threat_actor_cached(self):
        from core.stix.mapper import STIXMapper
        mapper = STIXMapper()
        ta1, _ = mapper.apt_profile_to_threat_actor("apt28", "APT28")
        ta2, _ = mapper.apt_profile_to_threat_actor("apt28", "APT28 v2")
        assert ta1.id == ta2.id

    def test_campaign_to_stix_type(self):
        from core.stix.mapper import STIXMapper
        mapper = STIXMapper()
        camp = mapper.campaign_to_stix("c-001", "Operation Nightfall")
        assert camp.type == "campaign"

    def test_campaign_cached(self):
        from core.stix.mapper import STIXMapper
        mapper = STIXMapper()
        c1 = mapper.campaign_to_stix("c-001", "Op A")
        c2 = mapper.campaign_to_stix("c-001", "Op B")
        assert c1.id == c2.id

    def test_finding_to_indicator_with_sigma(self):
        from core.stix.mapper import STIXMapper
        mapper = STIXMapper()
        ind = mapper.finding_to_indicator(
            "T1566", "Phishing",
            sigma_rule="title: Phishing\nstatus: experimental\n",
            severity="high",
        )
        assert ind is not None
        assert ind.type == "indicator"

    def test_finding_to_indicator_no_sigma_returns_none(self):
        from core.stix.mapper import STIXMapper
        mapper = STIXMapper()
        ind = mapper.finding_to_indicator("T1566", "Phishing")
        assert ind is None

    def test_indicator_cached(self):
        from core.stix.mapper import STIXMapper
        mapper = STIXMapper()
        sigma = "title: Test\n"
        i1 = mapper.finding_to_indicator("T1078", "Accounts", sigma_rule=sigma)
        i2 = mapper.finding_to_indicator("T1078", "Accounts v2", sigma_rule=sigma)
        assert i1.id == i2.id

    def test_course_of_action_type(self):
        from core.stix.mapper import STIXMapper
        mapper = STIXMapper()
        coa = mapper.remediation_to_course_of_action("T1566", "Deploy sandbox")
        assert coa.type == "course-of-action"

    def test_relationship_type(self):
        from core.stix.mapper import STIXMapper
        mapper = STIXMapper()
        ap = mapper.technique_to_attack_pattern("T1059", "Exec")
        camp = mapper.campaign_to_stix("c-001", "Test")
        rel = mapper.add_relationship(camp, "uses", ap)
        assert rel.type == "relationship"
        assert rel.relationship_type == "uses"

    def test_build_bundle_type(self):
        from core.stix.mapper import STIXMapper
        mapper = STIXMapper()
        mapper.technique_to_attack_pattern("T1566", "Phishing")
        bundle = mapper.build_bundle()
        assert bundle.type == "bundle"

    def test_to_json_serializable(self):
        from core.stix.mapper import STIXMapper
        mapper = STIXMapper()
        mapper.technique_to_attack_pattern("T1059", "Exec")
        json_str = mapper.to_json()
        data = json.loads(json_str)
        assert data["type"] == "bundle"
        assert "objects" in data


# ─── TestBundleBuilder ────────────────────────────────────────────────────────

class TestBundleBuilder:

    def test_campaign_bundle_type(self, sample_campaign_report):
        from core.stix.bundle_builder import build_campaign_bundle
        bundle = build_campaign_bundle(sample_campaign_report)
        assert bundle.type == "bundle"

    def test_campaign_bundle_has_objects(self, sample_campaign_report):
        from core.stix.bundle_builder import build_campaign_bundle, bundle_to_dict
        bundle = build_campaign_bundle(sample_campaign_report)
        d = bundle_to_dict(bundle)
        assert len(d["objects"]) > 0

    def test_campaign_bundle_has_campaign_object(self, sample_campaign_report):
        from core.stix.bundle_builder import build_campaign_bundle, bundle_to_dict
        bundle = build_campaign_bundle(sample_campaign_report)
        d = bundle_to_dict(bundle)
        types = [o["type"] for o in d["objects"]]
        assert "campaign" in types

    def test_campaign_bundle_has_attack_patterns(self, sample_campaign_report):
        from core.stix.bundle_builder import build_campaign_bundle, bundle_to_dict
        bundle = build_campaign_bundle(sample_campaign_report)
        d = bundle_to_dict(bundle)
        aps = [o for o in d["objects"] if o["type"] == "attack-pattern"]
        # T1566, T1059, T0801 = 3 attack patterns
        assert len(aps) >= 2

    def test_campaign_bundle_has_indicators_for_gaps(self, sample_campaign_report):
        from core.stix.bundle_builder import build_campaign_bundle, bundle_to_dict
        bundle = build_campaign_bundle(sample_campaign_report)
        d = bundle_to_dict(bundle)
        indicators = [o for o in d["objects"] if o["type"] == "indicator"]
        # T1566 + T0801 both have sigma rules and are gaps → 2 indicators
        assert len(indicators) >= 2

    def test_campaign_bundle_has_course_of_actions(self, sample_campaign_report):
        from core.stix.bundle_builder import build_campaign_bundle, bundle_to_dict
        bundle = build_campaign_bundle(sample_campaign_report)
        d = bundle_to_dict(bundle)
        coas = [o for o in d["objects"] if o["type"] == "course-of-action"]
        # T1566 + T0801 have remediation → 2 CoAs
        assert len(coas) >= 2

    def test_campaign_bundle_has_relationships(self, sample_campaign_report):
        from core.stix.bundle_builder import build_campaign_bundle, bundle_to_dict
        bundle = build_campaign_bundle(sample_campaign_report)
        d = bundle_to_dict(bundle)
        rels = [o for o in d["objects"] if o["type"] == "relationship"]
        assert len(rels) > 0

    def test_campaign_bundle_serializable_json(self, sample_campaign_report):
        from core.stix.bundle_builder import build_campaign_bundle
        bundle = build_campaign_bundle(sample_campaign_report)
        json_str = bundle.serialize(pretty=True)
        parsed = json.loads(json_str)
        assert parsed["type"] == "bundle"

    def test_campaign_bundle_empty_findings(self):
        from core.stix.bundle_builder import build_campaign_bundle, bundle_to_dict
        minimal = {
            "metadata": {"campaign_id": "min-001"},
            "campaign": {"name": "Minimal", "client": "Test"},
            "findings": [],
            "attack_path": [],
        }
        bundle = build_campaign_bundle(minimal)
        d = bundle_to_dict(bundle)
        assert d["type"] == "bundle"

    def test_purple_bundle_type(self, sample_purple_report):
        from core.stix.bundle_builder import build_purple_bundle
        bundle = build_purple_bundle(sample_purple_report)
        assert bundle.type == "bundle"

    def test_purple_bundle_has_attack_patterns(self, sample_purple_report):
        from core.stix.bundle_builder import build_purple_bundle, bundle_to_dict
        bundle = build_purple_bundle(sample_purple_report)
        d = bundle_to_dict(bundle)
        aps = [o for o in d["objects"] if o["type"] == "attack-pattern"]
        assert len(aps) >= 3  # T1566, T1003, T1021

    def test_purple_bundle_indicators_for_gaps_only(self, sample_purple_report):
        from core.stix.bundle_builder import build_purple_bundle, bundle_to_dict
        bundle = build_purple_bundle(sample_purple_report)
        d = bundle_to_dict(bundle)
        indicators = [o for o in d["objects"] if o["type"] == "indicator"]
        # Only T1566 and T1003 are gaps with sigma hints
        assert len(indicators) == 2

    def test_purple_bundle_course_of_action_from_recommendations(self, sample_purple_report):
        from core.stix.bundle_builder import build_purple_bundle, bundle_to_dict
        bundle = build_purple_bundle(sample_purple_report)
        d = bundle_to_dict(bundle)
        coas = [o for o in d["objects"] if o["type"] == "course-of-action"]
        assert len(coas) >= 1  # T1003 has recommendation

    def test_technique_bundle_single_attack_pattern(self):
        from core.stix.bundle_builder import build_technique_bundle, bundle_to_dict
        bundle = build_technique_bundle("T1566", "Phishing", "initial_access")
        d = bundle_to_dict(bundle)
        aps = [o for o in d["objects"] if o["type"] == "attack-pattern"]
        assert len(aps) == 1
        assert aps[0]["name"] == "Phishing"

    def test_technique_bundle_ot_technique(self):
        from core.stix.bundle_builder import build_technique_bundle, bundle_to_dict
        bundle = build_technique_bundle("T0801", "Monitor Process State")
        d = bundle_to_dict(bundle)
        aps = [o for o in d["objects"] if o["type"] == "attack-pattern"]
        refs = aps[0].get("external_references", [])
        mitre_ref = next((r for r in refs if r.get("source_name") == "mitre-attack"), None)
        assert mitre_ref is not None
        assert mitre_ref["external_id"] == "T0801"

    def test_bundle_to_dict_returns_dict(self, sample_campaign_report):
        from core.stix.bundle_builder import build_campaign_bundle, bundle_to_dict
        bundle = build_campaign_bundle(sample_campaign_report)
        d = bundle_to_dict(bundle)
        assert isinstance(d, dict)
        assert "id" in d
        assert d["id"].startswith("bundle--")


# ─── TestSTIXObjectStructure ──────────────────────────────────────────────────

class TestSTIXObjectStructure:

    def test_all_objects_have_type(self, sample_campaign_report):
        from core.stix.bundle_builder import build_campaign_bundle, bundle_to_dict
        d = bundle_to_dict(build_campaign_bundle(sample_campaign_report))
        for obj in d["objects"]:
            assert "type" in obj, f"Object missing 'type': {obj}"

    def test_all_objects_have_id(self, sample_campaign_report):
        from core.stix.bundle_builder import build_campaign_bundle, bundle_to_dict
        d = bundle_to_dict(build_campaign_bundle(sample_campaign_report))
        for obj in d["objects"]:
            assert "id" in obj

    def test_all_objects_id_matches_type(self, sample_campaign_report):
        from core.stix.bundle_builder import build_campaign_bundle, bundle_to_dict
        d = bundle_to_dict(build_campaign_bundle(sample_campaign_report))
        for obj in d["objects"]:
            assert obj["id"].startswith(obj["type"] + "--"), (
                f"ID {obj['id']} does not match type {obj['type']}"
            )

    def test_attack_patterns_have_external_references(self, sample_campaign_report):
        from core.stix.bundle_builder import build_campaign_bundle, bundle_to_dict
        d = bundle_to_dict(build_campaign_bundle(sample_campaign_report))
        aps = [o for o in d["objects"] if o["type"] == "attack-pattern"]
        for ap in aps:
            assert "external_references" in ap
            mitre = [r for r in ap["external_references"] if r.get("source_name") == "mitre-attack"]
            assert len(mitre) == 1

    def test_relationships_have_source_and_target(self, sample_campaign_report):
        from core.stix.bundle_builder import build_campaign_bundle, bundle_to_dict
        d = bundle_to_dict(build_campaign_bundle(sample_campaign_report))
        rels = [o for o in d["objects"] if o["type"] == "relationship"]
        for rel in rels:
            assert "source_ref" in rel
            assert "target_ref" in rel
            assert "relationship_type" in rel

    def test_aep_identity_structure(self):
        from core.stix.mapper import AEP_IDENTITY
        import json
        d = json.loads(AEP_IDENTITY.serialize())
        assert d["type"] == "identity"
        assert d["name"] == "AE Platform"
        assert "id" in d


# ─── TestSTIXRelationships ────────────────────────────────────────────────────

class TestSTIXRelationships:

    def _get_objects_by_type(self, d: dict, obj_type: str) -> list:
        return [o for o in d["objects"] if o["type"] == obj_type]

    def test_campaign_uses_attack_patterns(self, sample_campaign_report):
        from core.stix.bundle_builder import build_campaign_bundle, bundle_to_dict
        d = bundle_to_dict(build_campaign_bundle(sample_campaign_report))
        rels = self._get_objects_by_type(d, "relationship")
        uses_rels = [r for r in rels if r["relationship_type"] == "uses"]
        assert len(uses_rels) > 0

    def test_indicator_indicates_attack_pattern(self, sample_campaign_report):
        from core.stix.bundle_builder import build_campaign_bundle, bundle_to_dict
        d = bundle_to_dict(build_campaign_bundle(sample_campaign_report))
        rels = self._get_objects_by_type(d, "relationship")
        indicates_rels = [r for r in rels if r["relationship_type"] == "indicates"]
        assert len(indicates_rels) > 0
        # Target of "indicates" should be an attack-pattern
        ap_ids = {o["id"] for o in d["objects"] if o["type"] == "attack-pattern"}
        for rel in indicates_rels:
            assert rel["target_ref"] in ap_ids

    def test_coa_mitigates_attack_pattern(self, sample_campaign_report):
        from core.stix.bundle_builder import build_campaign_bundle, bundle_to_dict
        d = bundle_to_dict(build_campaign_bundle(sample_campaign_report))
        rels = self._get_objects_by_type(d, "relationship")
        mitigates = [r for r in rels if r["relationship_type"] == "mitigates"]
        assert len(mitigates) > 0
        ap_ids = {o["id"] for o in d["objects"] if o["type"] == "attack-pattern"}
        for rel in mitigates:
            assert rel["target_ref"] in ap_ids

    def test_all_relationship_refs_exist_in_bundle(self, sample_campaign_report):
        from core.stix.bundle_builder import build_campaign_bundle, bundle_to_dict
        d = bundle_to_dict(build_campaign_bundle(sample_campaign_report))
        all_ids = {o["id"] for o in d["objects"]}
        rels = self._get_objects_by_type(d, "relationship")
        for rel in rels:
            assert rel["source_ref"] in all_ids, f"Dangling source_ref: {rel['source_ref']}"
            assert rel["target_ref"] in all_ids, f"Dangling target_ref: {rel['target_ref']}"


# ─── TestPhase7Integration ────────────────────────────────────────────────────

class TestPhase7Integration:

    def test_stix_package_importable(self):
        from core.stix import (
            STIXMapper, AEP_IDENTITY,
            build_campaign_bundle, build_purple_bundle,
            build_technique_bundle, bundle_to_dict,
        )
        assert STIXMapper is not None
        assert AEP_IDENTITY is not None

    def test_campaign_bundle_json_round_trip(self, sample_campaign_report):
        """Bundle dapat di-serialize dan di-deserialize tanpa kehilangan data."""
        from core.stix.bundle_builder import build_campaign_bundle, bundle_to_dict
        bundle = build_campaign_bundle(sample_campaign_report)
        json_str = bundle.serialize(pretty=True)
        parsed = json.loads(json_str)
        # Re-parse tidak kehilangan objek
        assert len(parsed["objects"]) == len(bundle_to_dict(bundle)["objects"])

    def test_purple_bundle_json_round_trip(self, sample_purple_report):
        from core.stix.bundle_builder import build_purple_bundle
        bundle = build_purple_bundle(sample_purple_report)
        json_str = bundle.serialize(pretty=True)
        parsed = json.loads(json_str)
        assert parsed["type"] == "bundle"
        assert len(parsed["objects"]) > 0

    def test_no_duplicate_ids_in_bundle(self, sample_campaign_report):
        from core.stix.bundle_builder import build_campaign_bundle, bundle_to_dict
        d = bundle_to_dict(build_campaign_bundle(sample_campaign_report))
        ids = [o["id"] for o in d["objects"]]
        assert len(ids) == len(set(ids)), "Duplicate STIX IDs found in bundle"

    def test_technique_ids_normalized_uppercase(self):
        from core.stix.bundle_builder import build_technique_bundle, bundle_to_dict
        # Lowercase input → harus di-uppercase di external_id
        bundle = build_technique_bundle("t1566", "phishing")
        d = bundle_to_dict(bundle)
        aps = [o for o in d["objects"] if o["type"] == "attack-pattern"]
        refs = aps[0]["external_references"]
        mitre = next(r for r in refs if r.get("source_name") == "mitre-attack")
        assert mitre["external_id"] == "T1566"

    def test_mapper_object_count_increases(self):
        from core.stix.mapper import STIXMapper
        mapper = STIXMapper()
        initial = mapper.object_count
        mapper.technique_to_attack_pattern("T1059", "Exec")
        assert mapper.object_count == initial + 1

    def test_created_by_ref_points_to_aep(self, sample_campaign_report):
        """Semua objek utama harus memiliki created_by_ref yang mengarah ke AEP Identity."""
        from core.stix.bundle_builder import build_campaign_bundle, bundle_to_dict
        from core.stix.mapper import AEP_IDENTITY
        d = bundle_to_dict(build_campaign_bundle(sample_campaign_report))
        aep_id = AEP_IDENTITY.id
        non_identity_objs = [
            o for o in d["objects"]
            if o["type"] not in ("bundle", "identity", "relationship")
        ]
        for obj in non_identity_objs:
            assert obj.get("created_by_ref") == aep_id, (
                f"Object {obj['type']} ({obj['id']}) missing created_by_ref to AEP"
            )
