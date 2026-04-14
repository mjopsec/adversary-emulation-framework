"""
Test suite Phase 3 — AI Decision Engine Penuh.
Memverifikasi Campaign Parser, Campaign Builder, Pivot Engine, Attack Path Graph,
dan integrasi semua komponen Phase 3.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ─── Campaign Parser Tests ────────────────────────────────────────────────────

class TestCampaignParser:
    """Test Campaign-as-Code parser (YAML/JSON → ParsedCampaign)."""

    def _make_valid_dict(self, **overrides) -> dict:
        """Template campaign definition yang valid."""
        base = {
            "version": "1.0",
            "metadata": {
                "name": "Test Campaign APT28",
                "client": "PT Test Client",
                "engagement_type": "greybox",
                "environment": "it",
                "rules_of_engagement": "Tidak merusak production, izin tertulis sudah ada.",
                "emergency_contact": "SOC: +62-21-0000",
                "objectives": ["lateral_movement", "credential_theft"],
                "apt_profile": "APT28",
                "production_safe": True,
            },
            "scope": {
                "ips": ["192.168.1.0/24"],
                "domains": ["corp.test.local"],
                "exclude": ["192.168.1.1"],
            },
            "steps": [
                {
                    "id": "step_1",
                    "phase": "initial-access",
                    "technique": "T1566",
                    "method": "spearphishing_link",
                    "risk": "medium",
                    "notes": "Target HR department",
                },
                {
                    "id": "step_2",
                    "phase": "execution",
                    "technique": "T1059",
                    "depends_on": "step_1",
                    "risk": "medium",
                },
                {
                    "id": "step_3",
                    "phase": "credential-access",
                    "technique": "T1003",
                    "depends_on": ["step_2"],
                    "risk": "high",
                    "fallback": "T1078",
                },
            ],
        }
        base.update(overrides)
        return base

    def test_parse_valid_dict(self) -> None:
        from core.intel.campaign_parser import CampaignParser
        parser = CampaignParser()
        parsed = parser.parse_dict(self._make_valid_dict())

        assert parsed.name == "Test Campaign APT28"
        assert parsed.client_name == "PT Test Client"
        assert parsed.engagement_type == "greybox"
        assert parsed.environment_type == "it"
        assert parsed.production_safe is True
        assert parsed.apt_profile_name == "APT28"

    def test_parse_scope(self) -> None:
        from core.intel.campaign_parser import CampaignParser
        parsed = CampaignParser().parse_dict(self._make_valid_dict())

        assert "192.168.1.0/24" in parsed.scope.ips
        assert "corp.test.local" in parsed.scope.domains
        assert "192.168.1.1" in parsed.scope.exclude

    def test_parse_steps_count(self) -> None:
        from core.intel.campaign_parser import CampaignParser
        parsed = CampaignParser().parse_dict(self._make_valid_dict())
        assert len(parsed.steps) == 3

    def test_parse_steps_technique_ids(self) -> None:
        from core.intel.campaign_parser import CampaignParser
        parsed = CampaignParser().parse_dict(self._make_valid_dict())
        technique_ids = [s.technique_id for s in parsed.steps]
        assert "T1566" in technique_ids
        assert "T1059" in technique_ids
        assert "T1003" in technique_ids

    def test_parse_step_fallback(self) -> None:
        from core.intel.campaign_parser import CampaignParser
        parsed = CampaignParser().parse_dict(self._make_valid_dict())
        step_3 = next(s for s in parsed.steps if s.technique_id == "T1003")
        assert step_3.fallback_technique == "T1078"

    def test_parse_step_method(self) -> None:
        from core.intel.campaign_parser import CampaignParser
        parsed = CampaignParser().parse_dict(self._make_valid_dict())
        step_1 = next(s for s in parsed.steps if s.technique_id == "T1566")
        assert step_1.method == "spearphishing_link"

    def test_steps_ordered_by_dependency(self) -> None:
        from core.intel.campaign_parser import CampaignParser
        parsed = CampaignParser().parse_dict(self._make_valid_dict())
        # step_1 harus sebelum step_2 (step_2 depends_on step_1)
        orders = {s.technique_id: s.order_index for s in parsed.steps}
        assert orders["T1566"] < orders["T1059"]
        assert orders["T1059"] < orders["T1003"]

    def test_parse_missing_required_field_raises(self) -> None:
        from core.intel.campaign_parser import CampaignParser
        data = self._make_valid_dict()
        del data["metadata"]["name"]
        with pytest.raises(ValueError, match="name"):
            CampaignParser().parse_dict(data)

    def test_parse_invalid_engagement_type_raises(self) -> None:
        from core.intel.campaign_parser import CampaignParser
        data = self._make_valid_dict()
        data["metadata"]["engagement_type"] = "ninja"
        with pytest.raises(ValueError, match="engagement_type"):
            CampaignParser().parse_dict(data)

    def test_parse_environment_alias(self) -> None:
        from core.intel.campaign_parser import CampaignParser
        data = self._make_valid_dict()
        data["metadata"]["environment"] = "ics"  # Alias untuk "ot"
        parsed = CampaignParser().parse_dict(data)
        assert parsed.environment_type == "ot"

    def test_parse_ot_environment(self) -> None:
        from core.intel.campaign_parser import CampaignParser
        data = self._make_valid_dict()
        data["metadata"]["environment"] = "ot"
        data["steps"][0]["technique"] = "T0801"
        parsed = CampaignParser().parse_dict(data)
        assert parsed.environment_type == "ot"

    def test_parse_warns_empty_scope(self) -> None:
        from core.intel.campaign_parser import CampaignParser
        data = self._make_valid_dict()
        data["scope"] = {"ips": [], "domains": []}
        parsed = CampaignParser().parse_dict(data)
        assert len(parsed.parse_warnings) > 0
        assert any("Scope" in w or "scope" in w for w in parsed.parse_warnings)

    def test_parse_warns_empty_roe(self) -> None:
        from core.intel.campaign_parser import CampaignParser
        data = self._make_valid_dict()
        data["metadata"]["rules_of_engagement"] = ""
        parsed = CampaignParser().parse_dict(data)
        assert any("rules_of_engagement" in w for w in parsed.parse_warnings)

    def test_parse_date_iso_format(self) -> None:
        from core.intel.campaign_parser import CampaignParser
        data = self._make_valid_dict()
        data["metadata"]["start_date"] = "2026-01-15"
        data["metadata"]["end_date"] = "2026-01-30"
        parsed = CampaignParser().parse_dict(data)
        assert parsed.start_date is not None
        assert parsed.start_date.year == 2026
        assert parsed.start_date.month == 1

    def test_technique_id_normalized_uppercase(self) -> None:
        from core.intel.campaign_parser import CampaignParser
        data = self._make_valid_dict()
        data["steps"][0]["technique"] = "t1566"  # lowercase
        parsed = CampaignParser().parse_dict(data)
        step_1 = parsed.steps[0]
        assert step_1.technique_id == "T1566"

    def test_to_campaign_create_dict(self) -> None:
        from core.intel.campaign_parser import CampaignParser
        parsed = CampaignParser().parse_dict(self._make_valid_dict())
        result = parsed.to_campaign_create_dict()
        assert result["name"] == "Test Campaign APT28"
        assert result["client_name"] == "PT Test Client"
        assert isinstance(result["target_ips"], list)
        assert result["production_safe_mode"] is True

    def test_to_steps_create_list(self) -> None:
        from core.intel.campaign_parser import CampaignParser
        parsed = CampaignParser().parse_dict(self._make_valid_dict())
        steps = parsed.to_steps_create_list()
        assert len(steps) == 3
        for step in steps:
            assert "technique_id" in step
            assert "phase" in step
            assert "order_index" in step

    def test_parse_yaml_string(self) -> None:
        from core.intel.campaign_parser import CampaignParser
        yaml_content = """
version: "1.0"
metadata:
  name: YAML Campaign Test
  client: PT YAML Client
  engagement_type: blackbox
  environment: it
  rules_of_engagement: Scope terbatas pada 192.168.1.0/24
  emergency_contact: admin@test.com
scope:
  ips:
    - "192.168.1.0/24"
steps:
  - id: s1
    phase: initial-access
    technique: T1566
    risk: low
"""
        parsed = CampaignParser().parse_string(yaml_content, format="yaml")
        assert parsed.name == "YAML Campaign Test"
        assert parsed.engagement_type == "blackbox"
        assert len(parsed.steps) == 1

    def test_load_campaign_dict_convenience(self) -> None:
        from core.intel.campaign_parser import load_campaign_dict
        parsed = load_campaign_dict(self._make_valid_dict())
        assert parsed.name == "Test Campaign APT28"

    def test_load_campaign_yaml_convenience(self) -> None:
        from core.intel.campaign_parser import load_campaign_yaml
        yaml_str = """
metadata:
  name: "Quick YAML Test"
  client: "Test"
  engagement_type: greybox
  environment: it
  rules_of_engagement: RoE test
  emergency_contact: test@test.com
scope:
  ips: ["10.0.0.0/8"]
steps: []
"""
        parsed = load_campaign_yaml(yaml_str)
        assert parsed.name == "Quick YAML Test"


# ─── Campaign Builder Tests ───────────────────────────────────────────────────

class TestCampaignBuilder:
    """Test auto-campaign builder (objectives → GeneratedCampaign)."""

    def _make_mock_candidate(self, technique_id: str, tactic: str, score: float = 0.6) -> MagicMock:
        candidate = MagicMock()
        candidate.technique_id = technique_id
        candidate.name = f"Mock Technique {technique_id}"
        candidate.tactic = tactic
        candidate.risk_level = "medium"
        candidate.score = score
        candidate.is_registered = True
        candidate.environment = "it"
        return candidate

    @pytest.mark.asyncio
    async def test_builder_returns_generated_campaign(self) -> None:
        from core.engine.campaign_builder import CampaignBuilder, BuilderConfig
        from unittest.mock import AsyncMock, MagicMock, patch

        settings = MagicMock()
        settings.has_ai_configured = False

        ai_engine = MagicMock()
        ai_engine._ai_available = False

        mock_session = AsyncMock()

        with patch("core.engine.campaign_builder.TechniqueSelector") as MockSelector:
            mock_selector = AsyncMock()
            MockSelector.return_value = mock_selector

            candidates = [self._make_mock_candidate("T1566", "initial-access", 0.8)]
            mock_selector.get_candidates = AsyncMock(return_value=candidates)
            mock_selector._filter_tactics_by_objectives = MagicMock(
                return_value=["initial-access"]
            )

            # Mock APT profile loading
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none = MagicMock(return_value=None)
            mock_session.execute = AsyncMock(return_value=mock_result)

            builder = CampaignBuilder(
                session=mock_session,
                settings=settings,
                ai_engine=ai_engine,
            )

            config = BuilderConfig(
                environment="it",
                objectives=["initial_access"],
                max_steps=5,
            )

            generated = await builder.build("Test Campaign", config)

            assert generated.name == "Test Campaign"
            assert generated.total_steps >= 0
            assert isinstance(generated.steps, list)

    @pytest.mark.asyncio
    async def test_builder_config_defaults(self) -> None:
        from core.engine.campaign_builder import BuilderConfig
        config = BuilderConfig()
        assert config.environment == "it"
        assert config.max_risk == "high"
        assert config.max_steps == 12
        assert config.prefer_registered is True

    def test_generated_campaign_to_dict(self) -> None:
        from core.engine.campaign_builder import GeneratedCampaign, GeneratedStep
        step = GeneratedStep(
            order_index=0,
            phase="initial-access",
            technique_id="T1566",
            technique_name="Phishing",
            risk_level="medium",
            score=0.75,
            is_implemented=True,
            ai_reasoning="Teknik ini cocok untuk initial access.",
        )
        campaign = GeneratedCampaign(
            name="Test",
            description="Test desc",
            environment="it",
            objectives=["initial_access"],
            steps=[step],
        )
        result = campaign.to_dict()
        assert result["name"] == "Test"
        assert result["total_steps"] == 1
        assert result["implemented_steps"] == 1
        assert result["implementation_coverage"] == 1.0
        assert len(result["steps"]) == 1

    def test_generated_campaign_risk_summary(self) -> None:
        from core.engine.campaign_builder import GeneratedCampaign, GeneratedStep

        steps = [
            GeneratedStep(0, "initial-access", "T1566", "Phishing", "medium", 0.7, True),
            GeneratedStep(1, "execution", "T1059", "Scripting", "high", 0.6, True),
            GeneratedStep(2, "credential-access", "T1003", "Cred Dump", "critical", 0.5, True),
        ]
        campaign = GeneratedCampaign("Test", "desc", "it", [], steps)
        assert campaign.risk_summary["medium"] == 1
        assert campaign.risk_summary["high"] == 1
        assert campaign.risk_summary["critical"] == 1

    def test_generated_campaign_to_steps_create(self) -> None:
        from core.engine.campaign_builder import GeneratedCampaign, GeneratedStep

        step = GeneratedStep(
            order_index=0,
            phase="initial-access",
            technique_id="T1566",
            technique_name="Phishing",
            risk_level="medium",
            score=0.8,
            is_implemented=True,
            ai_reasoning="Pilihan terbaik untuk initial access.",
            estimated_success_rate=0.7,
            fallback_technique_id="T1078",
        )
        campaign = GeneratedCampaign("Test", "desc", "it", [], [step])
        steps_create = campaign.to_campaign_steps_create()
        assert len(steps_create) == 1
        assert steps_create[0]["technique_id"] == "T1566"
        assert steps_create[0]["phase"] == "initial-access"
        assert steps_create[0]["risk_assessment"] == "medium"
        assert steps_create[0]["fallback_action"] == "T1078"


# ─── Pivot Engine Tests ───────────────────────────────────────────────────────

class TestPivotEngine:
    """Test pivot engine: failure classification, pivot selection, history."""

    def _make_engine(self) -> "PivotEngine":
        from core.engine.pivot_engine import PivotEngine
        mock_session = AsyncMock()
        mock_ai = MagicMock()
        mock_ai._ai_available = False
        engine = PivotEngine(session=mock_session, ai_engine=mock_ai)
        return engine

    def test_classify_failure_detected(self) -> None:
        from core.engine.pivot_engine import PivotEngine, FailureReason
        engine = self._make_engine()
        result = {"status": "failed", "result_detail": "", "detected": True}
        reason = engine._classify_failure(result)
        assert reason == FailureReason.DETECTED

    def test_classify_failure_scope_violation(self) -> None:
        from core.engine.pivot_engine import PivotEngine, FailureReason
        engine = self._make_engine()
        result = {"status": "aborted", "result_detail": "luar scope engagement", "detected": False}
        reason = engine._classify_failure(result)
        assert reason == FailureReason.SCOPE_VIOLATION

    def test_classify_failure_no_privilege(self) -> None:
        from core.engine.pivot_engine import PivotEngine, FailureReason
        engine = self._make_engine()
        result = {"status": "failed", "result_detail": "access denied - privilege required", "detected": False}
        reason = engine._classify_failure(result)
        assert reason == FailureReason.NO_PRIVILEGE

    def test_classify_failure_network(self) -> None:
        from core.engine.pivot_engine import PivotEngine, FailureReason
        engine = self._make_engine()
        result = {"status": "failed", "result_detail": "network connection refused by firewall", "detected": False}
        reason = engine._classify_failure(result)
        assert reason == FailureReason.NETWORK_BLOCKED

    def test_classify_failure_unknown(self) -> None:
        from core.engine.pivot_engine import PivotEngine, FailureReason
        engine = self._make_engine()
        result = {"status": "failed", "result_detail": "teknik gagal tanpa alasan jelas", "detected": False}
        reason = engine._classify_failure(result)
        assert reason == FailureReason.UNKNOWN

    def test_context_adjustments_for_detected(self) -> None:
        from core.engine.pivot_engine import PivotEngine, FailureReason
        engine = self._make_engine()
        adj = engine._recommend_context_adjustments(FailureReason.DETECTED, "T1059")
        assert adj.get("use_obfuscation") is True
        assert adj.get("stealth_mode") is True

    def test_context_adjustments_for_no_privilege(self) -> None:
        from core.engine.pivot_engine import PivotEngine, FailureReason
        engine = self._make_engine()
        adj = engine._recommend_context_adjustments(FailureReason.NO_PRIVILEGE, "T1059")
        assert adj.get("check_privileges") is True

    def test_pivot_history_add_and_count(self) -> None:
        from core.engine.pivot_engine import PivotHistory, PivotDecision, FailureReason
        from core.techniques.base import ExecutionStatus

        history = PivotHistory(campaign_id="test-campaign")
        decision = PivotDecision(
            failed_technique_id="T1566",
            failure_reason=FailureReason.DETECTED,
            execution_status=ExecutionStatus.FAILED,
            should_pivot=True,
            pivot_technique_id="T1078",
            pivot_tactic="initial-access",
        )
        history.add_pivot(decision)

        assert history.total_failures == 1
        assert history.total_pivots == 1
        assert history.get_pivot_rate() == 1.0

    def test_pivot_history_no_pivot(self) -> None:
        from core.engine.pivot_engine import PivotHistory, PivotDecision, FailureReason
        from core.techniques.base import ExecutionStatus

        history = PivotHistory(campaign_id="test-campaign")
        decision = PivotDecision(
            failed_technique_id="T1566",
            failure_reason=FailureReason.SCOPE_VIOLATION,
            execution_status=ExecutionStatus.ABORTED,
            should_pivot=False,
        )
        history.add_pivot(decision)

        assert history.total_failures == 1
        assert history.total_pivots == 0
        assert history.get_pivot_rate() == 0.0

    def test_pivot_history_was_technique_tried(self) -> None:
        from core.engine.pivot_engine import PivotHistory, PivotDecision, FailureReason
        from core.techniques.base import ExecutionStatus

        history = PivotHistory(campaign_id="test-campaign")
        decision = PivotDecision(
            failed_technique_id="T1566",
            failure_reason=FailureReason.UNKNOWN,
            execution_status=ExecutionStatus.FAILED,
            should_pivot=True,
            pivot_technique_id="T1078",
        )
        history.add_pivot(decision)

        assert history.was_technique_tried("T1566") is True
        assert history.was_technique_tried("T1059") is False

    def test_pivot_history_to_summary(self) -> None:
        from core.engine.pivot_engine import PivotHistory
        history = PivotHistory(campaign_id="test-campaign")
        summary = history.to_summary()
        assert summary["campaign_id"] == "test-campaign"
        assert summary["total_failures"] == 0
        assert summary["pivot_rate"] == 0.0

    def test_pivot_decision_to_dict(self) -> None:
        from core.engine.pivot_engine import PivotDecision, FailureReason
        from core.techniques.base import ExecutionStatus

        decision = PivotDecision(
            failed_technique_id="T1566",
            failure_reason=FailureReason.DETECTED,
            execution_status=ExecutionStatus.FAILED,
            should_pivot=True,
            pivot_technique_id="T1078",
            pivot_reasoning="Pivot karena terdeteksi.",
        )
        d = decision.to_dict()
        assert d["failed_technique"] == "T1566"
        assert d["should_pivot"] is True
        assert d["failure_reason"] == "detected"
        assert d["pivot_technique"] == "T1078"

    @pytest.mark.asyncio
    async def test_pivot_scope_violation_no_pivot(self) -> None:
        """ABORTED karena scope violation tidak boleh di-pivot."""
        from core.engine.pivot_engine import PivotEngine, FailureReason
        engine = self._make_engine()

        with patch.object(engine.selector, "get_candidates", return_value=[]):
            result = {
                "status": "aborted",
                "result_detail": "luar scope engagement",
                "detected": False,
            }
            decision = await engine.decide_pivot(
                campaign_id="campaign-1",
                failed_technique_id="T1566",
                current_tactic="initial-access",
                environment="it",
                execution_result=result,
            )
            assert decision.should_pivot is False
            assert decision.failure_reason == FailureReason.SCOPE_VIOLATION

    @pytest.mark.asyncio
    async def test_pivot_get_history(self) -> None:
        from core.engine.pivot_engine import PivotEngine
        engine = self._make_engine()
        history = engine.get_history("campaign-xyz")
        assert history.campaign_id == "campaign-xyz"
        assert history.total_failures == 0


# ─── Attack Path Graph Tests ──────────────────────────────────────────────────

class TestAttackPathGraph:
    """Test attack path graph: build, analysis, export."""

    def _make_executions(self) -> list[dict]:
        return [
            {
                "technique_id": "T1566",
                "technique_name": "Phishing",
                "tactic": "initial-access",
                "status": "success",
                "detected": False,
                "risk_level": "medium",
                "order_index": 0,
                "duration_seconds": 2.5,
                "target": "192.168.1.100",
                "artifacts_created": [],
                "is_pivot": False,
            },
            {
                "technique_id": "T1059",
                "technique_name": "Command Scripting",
                "tactic": "execution",
                "status": "success",
                "detected": True,
                "risk_level": "medium",
                "order_index": 1,
                "duration_seconds": 1.2,
                "target": "192.168.1.100",
                "artifacts_created": ["C:\\temp\\script.ps1"],
                "is_pivot": False,
            },
            {
                "technique_id": "T1003",
                "technique_name": "Credential Dumping",
                "tactic": "credential-access",
                "status": "failed",
                "detected": False,
                "risk_level": "high",
                "order_index": 2,
                "duration_seconds": 0.5,
                "target": "192.168.1.100",
                "artifacts_created": [],
                "is_pivot": False,
            },
            {
                "technique_id": "T1078",
                "technique_name": "Valid Accounts",
                "tactic": "credential-access",
                "status": "success",
                "detected": False,
                "risk_level": "medium",
                "order_index": 3,
                "duration_seconds": 1.8,
                "target": "192.168.1.100",
                "artifacts_created": [],
                "is_pivot": True,  # Pivot dari T1003 yang gagal
            },
        ]

    def test_build_from_executions_nodes(self) -> None:
        from core.graph.attack_path import AttackPathGraph
        graph = AttackPathGraph("campaign-1", "Test Campaign")
        graph.build_from_executions(self._make_executions())
        assert len(graph._nodes) == 4

    def test_build_from_executions_edges(self) -> None:
        from core.graph.attack_path import AttackPathGraph
        graph = AttackPathGraph("campaign-1", "Test Campaign")
        graph.build_from_executions(self._make_executions())
        # 4 nodes → 3 edges (linear sequence)
        assert len(graph._edges) == 3

    def test_detection_gaps(self) -> None:
        from core.graph.attack_path import AttackPathGraph
        graph = AttackPathGraph("campaign-1", "Test Campaign")
        graph.build_from_executions(self._make_executions())
        gaps = graph.get_detection_gaps()
        # T1566 (success, not detected) dan T1078 (success, not detected) = gaps
        assert "T1566" in gaps
        assert "T1078" in gaps
        # T1059 terdeteksi — bukan gap
        assert "T1059" not in gaps
        # T1003 gagal — bukan success, tidak masuk ke gap
        assert "T1003" not in gaps

    def test_pivot_sequences(self) -> None:
        from core.graph.attack_path import AttackPathGraph
        graph = AttackPathGraph("campaign-1", "Test Campaign")
        graph.build_from_executions(self._make_executions())
        pivots = graph.get_pivot_sequences()
        # Edge T1003 → T1078 adalah pivot
        assert ("T1003", "T1078") in pivots

    def test_statistics_computed(self) -> None:
        from core.graph.attack_path import AttackPathGraph
        graph = AttackPathGraph("campaign-1", "Test Campaign")
        graph.build_from_executions(self._make_executions())
        stats = graph.compute_statistics()

        assert stats["total_nodes"] == 4
        assert stats["success_count"] == 3   # T1566, T1059, T1078
        assert stats["failed_count"] == 1    # T1003
        assert stats["detected_count"] == 1  # T1059
        assert stats["undetected_count"] == 2  # T1566, T1078
        assert stats["pivot_count"] == 1     # T1003 → T1078

    def test_to_dict_structure(self) -> None:
        from core.graph.attack_path import AttackPathGraph
        graph = AttackPathGraph("campaign-1", "Test Campaign")
        graph.build_from_executions(self._make_executions())
        result = graph.to_dict()

        assert result["campaign_id"] == "campaign-1"
        assert "nodes" in result
        assert "edges" in result
        assert "statistics" in result
        assert len(result["nodes"]) == 4

    def test_to_navigator_layer_structure(self) -> None:
        from core.graph.attack_path import AttackPathGraph
        graph = AttackPathGraph("campaign-1", "Test Campaign")
        graph.build_from_executions(self._make_executions())
        layer = graph.to_navigator_layer()

        assert layer["domain"] == "enterprise-attack"
        assert "techniques" in layer
        assert len(layer["techniques"]) == 4
        # Cek structure setiap teknik
        for tech in layer["techniques"]:
            assert "techniqueID" in tech
            assert "color" in tech
            assert "score" in tech

    def test_navigator_colors_correct(self) -> None:
        from core.graph.attack_path import AttackPathGraph, PathNode
        graph = AttackPathGraph("campaign-1", "Test")
        # Success + not detected = RED (gap)
        node_gap = PathNode("T1566", "Phishing", "initial-access", "success", detected=False)
        assert node_gap.color_for_navigator == "#f44336"

        # Success + detected = GREEN (good)
        node_detected = PathNode("T1059", "Scripting", "execution", "success", detected=True)
        assert node_detected.color_for_navigator == "#4CAF50"

        # Failed = GRAY
        node_failed = PathNode("T1003", "Cred Dump", "credential-access", "failed", detected=False)
        assert node_failed.color_for_navigator == "#999999"

    def test_to_graphviz_dot(self) -> None:
        from core.graph.attack_path import AttackPathGraph
        graph = AttackPathGraph("campaign-1", "Test Campaign")
        graph.build_from_executions(self._make_executions())
        dot = graph.to_graphviz_dot()

        assert "digraph" in dot
        assert "T1566" in dot
        assert "T1059" in dot
        assert "->" in dot

    def test_empty_graph_statistics(self) -> None:
        from core.graph.attack_path import AttackPathGraph
        graph = AttackPathGraph("campaign-empty", "Empty")
        stats = graph.compute_statistics()
        assert stats["total_nodes"] == 0

    def test_build_attack_path_factory(self) -> None:
        from core.graph.attack_path import build_attack_path
        graph = build_attack_path(
            campaign_id="factory-test",
            campaign_name="Factory Test",
            executions=self._make_executions(),
        )
        assert len(graph._nodes) == 4
        assert graph.campaign_id == "factory-test"

    def test_critical_path_returns_list(self) -> None:
        from core.graph.attack_path import AttackPathGraph
        graph = AttackPathGraph("campaign-1", "Test")
        graph.build_from_executions(self._make_executions())
        path = graph.get_critical_path()
        assert isinstance(path, list)
        # Hanya technique yang sukses yang masuk critical path (fallback linear)
        for tid in path:
            assert tid in graph._nodes

    def test_chokepoints_returns_list(self) -> None:
        from core.graph.attack_path import AttackPathGraph
        graph = AttackPathGraph("campaign-1", "Test")
        graph.build_from_executions(self._make_executions())
        chokepoints = graph.get_chokepoints()
        assert isinstance(chokepoints, list)


# ─── Integration Tests ────────────────────────────────────────────────────────

class TestPhase3Integration:
    """Test integrasi komponen Phase 3."""

    def test_parser_to_campaign_create_dict_valid_schema(self) -> None:
        """Hasil parser harus kompatibel dengan CampaignCreate schema."""
        from core.intel.campaign_parser import load_campaign_dict
        from core.schemas.campaign import CampaignCreate

        parsed = load_campaign_dict({
            "metadata": {
                "name": "Integration Test Campaign",
                "client": "PT Integration",
                "engagement_type": "greybox",
                "environment": "it",
                "rules_of_engagement": "Rules jelas dan tertulis di dokumen engagement.",
                "emergency_contact": "SOC: 0800-123",
            },
            "scope": {"ips": ["192.168.1.0/24"]},
            "steps": [],
        })

        campaign_dict = parsed.to_campaign_create_dict()
        # Harus bisa di-validate oleh CampaignCreate
        campaign = CampaignCreate(**campaign_dict)
        assert campaign.name == "Integration Test Campaign"
        assert campaign.engagement_type == "greybox"

    def test_attack_path_statistics_consistency(self) -> None:
        """Statistics harus konsisten dengan data nodes."""
        from core.graph.attack_path import build_attack_path

        executions = [
            {"technique_id": f"T100{i}", "technique_name": f"Tech {i}", "tactic": "execution",
             "status": "success" if i % 2 == 0 else "failed", "detected": i % 3 == 0,
             "risk_level": "medium", "order_index": i, "duration_seconds": 1.0,
             "artifacts_created": [], "is_pivot": False}
            for i in range(6)
        ]

        graph = build_attack_path("campaign-stat", "Stat Test", executions)
        stats = graph.compute_statistics()

        assert stats["success_count"] + stats["failed_count"] + stats.get("aborted_count", 0) == stats["total_nodes"]
        assert stats["detected_count"] + stats["undetected_count"] == stats["success_count"]

    def test_pivot_failure_reasons_cover_all_cases(self) -> None:
        """Semua FailureReason harus bisa di-instantiate dan punya value."""
        from core.engine.pivot_engine import FailureReason

        expected_reasons = [
            "detected", "no_privilege", "network_blocked",
            "target_unavailable", "wrong_environment",
            "scope_violation", "dependency_failed", "unknown",
        ]
        actual_values = {r.value for r in FailureReason}
        for reason in expected_reasons:
            assert reason in actual_values, f"FailureReason '{reason}' tidak ada"
