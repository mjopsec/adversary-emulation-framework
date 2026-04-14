"""
Test suite Phase 5 — Detection Validation + Purple Team Mode.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ─── DetectionValidator Tests ─────────────────────────────────────────────────

class TestDetectionValidator:

    def _make_validator(self):
        from core.detection.validator import DetectionValidator
        return DetectionValidator()

    def test_score_detected_full(self):
        v = self._make_validator()
        from core.detection.validator import DetectionQuality
        score = v.score_detection("T1566", "Phishing", "detected",
                                  detected_by="SIEM", triggered_alert="Alert-001")
        assert score.quality == DetectionQuality.FULL
        assert score.is_gap is False
        assert score.confidence >= 0.8

    def test_score_blocked_full(self):
        v = self._make_validator()
        from core.detection.validator import DetectionQuality
        score = v.score_detection("T1059", "Scripting", "blocked",
                                  detected_by="EDR")
        assert score.quality == DetectionQuality.FULL
        assert score.is_gap is False

    def test_score_missed_is_gap(self):
        v = self._make_validator()
        from core.detection.validator import DetectionQuality
        score = v.score_detection("T1003", "Cred Dump", "missed")
        assert score.quality == DetectionQuality.NONE
        assert score.is_gap is True
        assert score.confidence == 1.0   # 100% confident ini gap

    def test_score_partial(self):
        v = self._make_validator()
        from core.detection.validator import DetectionQuality
        score = v.score_detection("T1021", "Remote Svc", "partial",
                                  detection_latency=900.0)
        assert score.quality == DetectionQuality.PARTIAL
        assert score.is_gap is False

    def test_score_false_positive(self):
        v = self._make_validator()
        from core.detection.validator import DetectionQuality
        score = v.score_detection("T1078", "Valid Acct", "false_positive")
        assert score.quality == DetectionQuality.PARTIAL
        assert score.false_positive_risk == "high"

    def test_score_severity_gap(self):
        v = self._make_validator()
        score = v.score_detection("T1566", "Phishing", "missed")
        assert score.severity == "high"

    def test_score_severity_detected(self):
        v = self._make_validator()
        score = v.score_detection("T1566", "Phishing", "detected")
        assert score.severity == "low"

    def test_sigma_hint_known_technique(self):
        v = self._make_validator()
        sigma = v.generate_sigma_hint("T1566")
        assert "T1566" in sigma or "phishing" in sigma.lower() or "Phishing" in sigma
        assert "logsource" in sigma
        assert "detection" in sigma
        assert "aep-hint" in sigma

    def test_sigma_hint_t1059(self):
        v = self._make_validator()
        sigma = v.generate_sigma_hint("T1059")
        assert "powershell" in sigma.lower() or "Command" in sigma

    def test_sigma_hint_unknown_technique_uses_default(self):
        v = self._make_validator()
        sigma = v.generate_sigma_hint("T9999")
        assert "aep-hint" in sigma
        assert "logsource" in sigma

    def test_sigma_hint_ot_technique(self):
        v = self._make_validator()
        sigma = v.generate_sigma_hint("T0843")
        assert "T0843" in sigma or "plc" in sigma.lower() or "PLC" in sigma

    def test_sigma_hint_with_execution_method(self):
        v = self._make_validator()
        sigma = v.generate_sigma_hint("T1059", context={"execution_method": "powershell_encoded"})
        assert "powershell_encoded" in sigma

    def test_coverage_report_all_detected(self):
        v = self._make_validator()
        from core.detection.validator import DetectionScore, DetectionQuality
        scores = [
            DetectionScore("T1566", "Phishing", DetectionQuality.FULL, 0.9, 120.0, "SIEM", "Rule-1", "low"),
            DetectionScore("T1059", "Scripting", DetectionQuality.FULL, 0.9, 60.0, "EDR", "Rule-2", "low"),
        ]
        report = v.compute_coverage_report(scores)
        assert report.total_techniques == 2
        assert report.not_detected == 0
        assert report.detection_rate == 1.0
        assert report.gap_rate == 0.0

    def test_coverage_report_with_gaps(self):
        v = self._make_validator()
        from core.detection.validator import DetectionScore, DetectionQuality
        scores = [
            DetectionScore("T1566", "Phishing", DetectionQuality.FULL, 0.9, 120.0, "SIEM", "Rule-1", "low"),
            DetectionScore("T1003", "Cred Dump", DetectionQuality.NONE, 1.0, None, None, None, "low"),
            DetectionScore("T1059", "Scripting", DetectionQuality.PARTIAL, 0.7, 900.0, "Firewall", None, "medium"),
        ]
        report = v.compute_coverage_report(scores)
        assert report.total_techniques == 3
        assert report.not_detected == 1
        assert report.top_gaps == ["T1003"]
        assert report.gap_rate == pytest.approx(1/3, rel=0.01)

    def test_coverage_report_mttd(self):
        v = self._make_validator()
        from core.detection.validator import DetectionScore, DetectionQuality
        scores = [
            DetectionScore("T1566", "P", DetectionQuality.FULL, 0.9, 60.0, "SIEM", "R1", "low"),
            DetectionScore("T1059", "S", DetectionQuality.FULL, 0.9, 120.0, "EDR", "R2", "low"),
        ]
        report = v.compute_coverage_report(scores)
        assert report.mttd_seconds == pytest.approx(90.0)

    def test_coverage_report_empty(self):
        v = self._make_validator()
        report = v.compute_coverage_report([])
        assert report.total_techniques == 0
        assert report.detection_rate == 0.0

    def test_assess_severity_missed_it_high_impact(self):
        v = self._make_validator()
        sev = v.assess_finding_severity("T1003", "missed", False)
        assert sev == "high"

    def test_assess_severity_missed_ot_critical(self):
        v = self._make_validator()
        sev = v.assess_finding_severity("T0843", "missed", True)
        assert sev == "critical"

    def test_assess_severity_detected(self):
        v = self._make_validator()
        sev = v.assess_finding_severity("T1566", "detected", False)
        assert sev == "low"

    def test_coverage_by_tactic_it_vs_ot(self):
        v = self._make_validator()
        from core.detection.validator import DetectionScore, DetectionQuality
        scores = [
            DetectionScore("T1566", "P", DetectionQuality.FULL, 0.9, 60.0, "SIEM", "R", "low"),
            DetectionScore("T0801", "M", DetectionQuality.NONE, 1.0, None, None, None, "low"),
        ]
        report = v.compute_coverage_report(scores)
        assert "it" in report.coverage_by_tactic
        assert "ot" in report.coverage_by_tactic
        assert report.coverage_by_tactic["it"] == 1.0
        assert report.coverage_by_tactic["ot"] == 0.0


# ─── PurpleSession Model Tests ────────────────────────────────────────────────

class TestPurpleSessionModel:

    def _make_session(self, **kw) -> "PurpleSession":
        from core.models.purple_session import PurpleSession
        defaults = dict(name="Test Session", environment="it", status="active")
        defaults.update(kw)
        return PurpleSession(**defaults)

    def _make_event(self, response: str | None = None, is_gap: bool = False) -> "PurpleEvent":
        from core.models.purple_session import PurpleEvent
        return PurpleEvent(
            session_id="sess-1",
            technique_id="T1566",
            technique_name="Phishing",
            blue_response=response,
            is_gap=is_gap,
        )

    def test_session_is_active(self):
        ps = self._make_session(status="active")
        assert ps.is_active is True

    def test_session_is_not_active_draft(self):
        ps = self._make_session(status="draft")
        assert ps.is_active is False

    def test_session_gap_count(self):
        ps = self._make_session()
        ps.techniques_missed = 3
        assert ps.gap_count == 3

    def test_session_recompute_metrics(self):
        from core.models.purple_session import PurpleEvent
        ps = self._make_session()
        ps.events = [
            self._make_event("detected"),
            self._make_event("blocked"),
            self._make_event("missed", is_gap=True),
            self._make_event("partial"),
        ]
        ps.recompute_metrics()
        assert ps.total_techniques_tested == 4
        assert ps.techniques_detected == 1
        assert ps.techniques_blocked == 1
        assert ps.techniques_missed == 1
        assert ps.detection_coverage == pytest.approx(0.5)  # (1+1)/4

    def test_session_to_summary_keys(self):
        ps = self._make_session()
        ps.total_techniques_tested = 5
        ps.techniques_detected = 3
        ps.detection_coverage = 0.6
        s = ps.to_summary()
        assert "id" in s
        assert "detection_coverage" in s
        assert "total_tested" in s
        assert "gap_count" in s

    def test_event_was_detected_detected(self):
        event = self._make_event("detected")
        assert event.was_detected is True

    def test_event_was_detected_blocked(self):
        event = self._make_event("blocked")
        assert event.was_detected is True

    def test_event_was_detected_missed(self):
        event = self._make_event("missed")
        assert event.was_detected is False

    def test_event_remediation_steps_property(self):
        from core.models.purple_session import PurpleEvent
        event = PurpleEvent(session_id="s", technique_id="T1566")
        event.remediation_steps = ["Step 1", "Step 2"]
        assert len(event.remediation_steps) == 2

    def test_event_to_dict_structure(self):
        event = self._make_event("missed", is_gap=True)
        d = event.to_dict()
        assert "technique_id" in d
        assert "blue_response" in d
        assert "is_gap" in d
        assert d["is_gap"] is True

    def test_event_repr(self):
        event = self._make_event("missed", is_gap=True)
        r = repr(event)
        assert "PurpleEvent" in r
        assert "T1566" in r


# ─── PurpleTeamManager Tests ──────────────────────────────────────────────────

class TestPurpleTeamManager:

    def _make_manager(self):
        from core.detection.purple_team import PurpleTeamManager
        session = AsyncMock()
        return PurpleTeamManager(session)

    def test_valid_blue_responses_set(self):
        from core.detection.purple_team import VALID_BLUE_RESPONSES
        required = {"detected", "blocked", "partial", "missed", "false_positive"}
        assert required == VALID_BLUE_RESPONSES

    def test_compute_priority_critical(self):
        m = self._make_manager()
        assert m._compute_priority("critical") == 1

    def test_compute_priority_high(self):
        m = self._make_manager()
        assert m._compute_priority("high") == 2

    def test_compute_priority_low(self):
        m = self._make_manager()
        assert m._compute_priority("low") == 7

    def test_describe_gap_missed(self):
        m = self._make_manager()
        desc = m._describe_gap("T1003", "missed")
        assert "T1003" in desc
        assert "blind spot" in desc.lower() or "tidak terdeteksi" in desc.lower()

    def test_describe_gap_false_positive(self):
        m = self._make_manager()
        desc = m._describe_gap("T1059", "false_positive")
        assert "false positive" in desc.lower() or "noisy" in desc.lower()

    def test_generate_remediation_steps_missed(self):
        m = self._make_manager()
        steps = m._generate_remediation_steps("T1566", "missed")
        assert len(steps) >= 3
        # Steps harus berupa list of strings
        assert all(isinstance(s, str) for s in steps)

    def test_generate_remediation_steps_false_positive(self):
        m = self._make_manager()
        steps = m._generate_remediation_steps("T1059", "false_positive")
        # Harus ada langkah khusus untuk false positive
        combined = " ".join(steps).lower()
        assert "false positive" in combined or "exception" in combined or "tune" in combined

    def test_generate_remediation_critical_technique_has_urgent_note(self):
        m = self._make_manager()
        steps = m._generate_remediation_steps("T1003", "missed")
        combined = " ".join(steps)
        # T1003 adalah teknik kritis — harus ada catatan prioritas
        assert "PRIORITAS" in combined or "prioritas" in combined.lower() or "48" in combined

    @pytest.mark.asyncio
    async def test_record_blue_response_invalid_response(self):
        from core.detection.purple_team import PurpleTeamManager
        from core.models.purple_session import PurpleEvent

        session = AsyncMock()
        event = PurpleEvent(session_id="s", technique_id="T1566", blue_response=None)
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=event)
        session.execute = AsyncMock(return_value=mock_result)

        manager = PurpleTeamManager(session)
        with pytest.raises(ValueError, match="blue_response"):
            await manager.record_blue_response("event-1", "unknown_response")

    @pytest.mark.asyncio
    async def test_record_red_action_session_not_found(self):
        from core.detection.purple_team import PurpleTeamManager

        session = AsyncMock()
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=None)
        session.execute = AsyncMock(return_value=mock_result)

        manager = PurpleTeamManager(session)
        with pytest.raises(ValueError, match="tidak ditemukan"):
            await manager.record_red_team_action("nonexistent", "T1566")


# ─── PurpleRecommendation Tests ───────────────────────────────────────────────

class TestPurpleRecommendation:

    def test_recommendation_to_dict(self):
        from core.detection.purple_team import PurpleRecommendation
        rec = PurpleRecommendation(
            technique_id="T1003",
            priority=1,
            title="Deploy Credential Dump Detection",
            description="T1003 tidak terdeteksi dalam purple session.",
            steps=["Step A", "Step B"],
            sigma_hint="title: Sigma Hint\n...",
            estimated_effort="high",
            category="detection",
        )
        d = rec.to_dict()
        assert d["technique_id"] == "T1003"
        assert d["priority"] == 1
        assert len(d["steps"]) == 2
        assert "sigma_hint" in d

    def test_session_report_to_dict(self):
        from core.detection.purple_team import PurpleSessionReport, PurpleRecommendation
        report = PurpleSessionReport(
            session_id="sess-1",
            session_name="Test Session",
            environment="it",
            status="completed",
            total_tested=5,
            detected=3,
            blocked=1,
            missed=1,
            detection_coverage=0.8,
            mttd_seconds=120.0,
            top_gaps=["T1003"],
            recommendations=[
                PurpleRecommendation("T1003", 1, "Deploy T1003", "Gap", [], "", "high", "detection")
            ],
            coverage_by_tactic={"it": 0.8},
        )
        d = report.to_dict()
        assert d["session_id"] == "sess-1"
        assert d["metrics"]["detection_coverage"] == 0.8
        assert d["metrics"]["gap_rate"] == pytest.approx(0.2)
        assert len(d["recommendations"]) == 1
        assert d["top_gaps"] == ["T1003"]


# ─── Integration Tests ────────────────────────────────────────────────────────

class TestPhase5Integration:

    def test_validator_score_feeds_into_coverage_report(self):
        from core.detection.validator import DetectionValidator
        v = DetectionValidator()

        responses = [
            ("T1566", "Phishing", "detected", 120.0, "SIEM"),
            ("T1059", "Scripting", "missed", None, None),
            ("T1003", "Cred Dump", "blocked", 30.0, "EDR"),
            ("T1021", "Remote Svc", "partial", 900.0, "Firewall"),
            ("T0801", "Monitor", "missed", None, None),
        ]
        scores = [
            v.score_detection(tid, name, resp, lat, by)
            for tid, name, resp, lat, by in responses
        ]
        report = v.compute_coverage_report(scores)

        assert report.total_techniques == 5
        assert report.not_detected == 2  # T1059, T0801
        assert "T1059" in report.top_gaps
        assert "T0801" in report.top_gaps
        assert report.detection_rate < 1.0

    def test_sigma_hints_cover_all_registered_techniques(self):
        """Semua teknik yang terdaftar di registry harus punya Sigma hint."""
        from core.detection.validator import DetectionValidator, SIGMA_TEMPLATES
        from core.techniques.registry import TechniqueRegistry

        registry = TechniqueRegistry.instance()
        v = DetectionValidator()

        for tid in registry.list_all():
            sigma = v.generate_sigma_hint(tid)
            # Minimal harus ada struktur YAML dasar
            assert "logsource" in sigma, f"{tid}: Sigma hint tidak punya logsource"
            assert "detection" in sigma, f"{tid}: Sigma hint tidak punya detection block"

    def test_purple_session_metrics_after_multiple_events(self):
        """Recompute metrics harus konsisten setelah banyak events."""
        from core.models.purple_session import PurpleSession, PurpleEvent

        ps = PurpleSession(name="Test", environment="it", status="active")
        ps.events = [
            PurpleEvent(session_id="s", technique_id=f"T100{i}",
                        blue_response=resp, is_gap=(resp == "missed"))
            for i, resp in enumerate(
                ["detected", "missed", "blocked", "partial", "missed", "detected"]
            )
        ]
        ps.recompute_metrics()

        assert ps.total_techniques_tested == 6
        assert ps.techniques_missed == 2
        assert ps.techniques_detected == 2
        assert ps.techniques_blocked == 1
        assert ps.detection_coverage == pytest.approx(0.5)  # (2+1)/6
