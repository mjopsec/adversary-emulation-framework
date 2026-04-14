"""
Test dasar untuk verifikasi foundation Phase 1.
Memastikan semua komponen utama dapat diimport dan berfungsi.
"""

import pytest
from pydantic import ValidationError


# ─── Config Tests ─────────────────────────────────────────────────────────────

class TestConfig:
    def test_settings_loads(self) -> None:
        """Settings harus bisa diload tanpa error."""
        from core.config import Settings
        s = Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            anthropic_api_key=None,
        )
        assert s.app_name == "AE Platform"
        assert s.api_port == 8000
        assert s.default_production_safe is True

    def test_settings_singleton(self) -> None:
        """get_settings() harus mengembalikan instance yang sama."""
        from core.config import get_settings
        s1 = get_settings()
        s2 = get_settings()
        assert s1 is s2

    def test_has_ai_configured_false(self) -> None:
        from core.config import Settings
        s = Settings(anthropic_api_key=None)
        assert s.has_ai_configured is False

    def test_has_ai_configured_true(self) -> None:
        from core.config import Settings
        s = Settings(anthropic_api_key="sk-ant-test-key-1234567890")
        assert s.has_ai_configured is True


# ─── Schema Validation Tests ──────────────────────────────────────────────────

class TestSchemas:
    def test_campaign_create_valid(self) -> None:
        from core.schemas.campaign import CampaignCreate
        c = CampaignCreate(
            name="Test Campaign",
            client_name="Test Client",
            engagement_type="greybox",
            environment_type="it",
            target_ips=["192.168.1.0/24"],
            rules_of_engagement="Tidak ada aksi destruktif.",
            emergency_contact="security@test.com",
        )
        assert c.name == "Test Campaign"
        assert c.production_safe_mode is True

    def test_campaign_create_missing_scope_fails(self) -> None:
        from core.schemas.campaign import CampaignCreate
        with pytest.raises(ValidationError) as exc_info:
            CampaignCreate(
                name="Test",
                client_name="Test",
                engagement_type="blackbox",
                environment_type="ot",
                rules_of_engagement="RoE ada.",
                # Tidak ada target_ips atau target_domains
            )
        assert "Scope tidak boleh kosong" in str(exc_info.value)

    def test_campaign_create_missing_roe_fails(self) -> None:
        from core.schemas.campaign import CampaignCreate
        with pytest.raises(ValidationError) as exc_info:
            CampaignCreate(
                name="Test",
                client_name="Test",
                engagement_type="blackbox",
                environment_type="it",
                target_ips=["10.0.0.0/8"],
                # Tidak ada rules_of_engagement
            )
        assert "Rules of Engagement" in str(exc_info.value)

    def test_apt_profile_valid(self) -> None:
        from core.schemas.apt_profile import APTProfileCreate
        p = APTProfileCreate(
            name="Custom APT",
            motivation="espionage",
            sophistication="high",
        )
        assert p.targets_ot is False
        assert p.is_custom is True

    def test_technique_id_pattern(self) -> None:
        from core.schemas.campaign import CampaignStepCreate
        # Valid IDs
        CampaignStepCreate(
            order_index=0,
            phase="initial_access",
            technique_id="T1566",
        )
        CampaignStepCreate(
            order_index=1,
            phase="execution",
            technique_id="T1566.001",
        )

    def test_invalid_technique_id_fails(self) -> None:
        from core.schemas.campaign import CampaignStepCreate
        with pytest.raises(ValidationError):
            CampaignStepCreate(
                order_index=0,
                phase="initial_access",
                technique_id="invalid-id",
            )


# ─── Technique Base Tests ─────────────────────────────────────────────────────

class TestTechniqueBase:
    def test_context_in_scope(self) -> None:
        from core.techniques.base import TechniqueContext
        ctx = TechniqueContext(
            target_host="192.168.1.10",
            scope_ips=["192.168.1.0/24"],
            excluded_targets=["192.168.1.1"],
        )
        assert ctx.is_in_scope("192.168.1.10") is True
        assert ctx.is_in_scope("192.168.1.1") is False  # Excluded
        assert ctx.is_in_scope("10.0.0.1") is False      # Di luar scope

    def test_context_out_of_scope(self) -> None:
        from core.techniques.base import TechniqueContext
        ctx = TechniqueContext(
            target_host="192.168.2.10",
            scope_ips=["192.168.1.0/24"],
        )
        assert ctx.is_in_scope("192.168.2.10") is False

    def test_result_duration_computed(self) -> None:
        from datetime import datetime, timedelta
        from core.techniques.base import TechniqueResult, ExecutionStatus
        result = TechniqueResult(
            status=ExecutionStatus.SUCCESS,
            technique_id="T1566",
            target="192.168.1.10",
        )
        # Set started_at ke 5 detik yang lalu, lalu panggil mark_completed()
        result.started_at = datetime.utcnow() - timedelta(seconds=5)
        result.mark_completed()
        # Duration harus sekitar 5 detik (±1 detik toleransi untuk overhead test)
        assert result.duration_seconds is not None
        assert 4.0 <= result.duration_seconds <= 10.0


# ─── AI Decision Engine Tests ──────────────────────────────────────────────────

class TestAIDecisionEngine:
    def test_deterministic_mode_validation(self) -> None:
        from core.config import Settings
        from core.engine.ai_decision import AIDecisionEngine
        settings = Settings(anthropic_api_key=None)
        engine = AIDecisionEngine(settings)
        assert engine._ai_available is False

        result = engine._deterministic_validate({
            "client_name": "Test Client",
            "target_ips": ["10.0.0.0/8"],
            "rules_of_engagement": "RoE lengkap",
            "emergency_contact": "security@test.com",
            "start_date": "2024-01-01",
            "end_date": "2024-03-31",
        })
        assert result.is_valid is True
        assert len(result.missing_fields) == 0

    def test_deterministic_validation_missing_fields(self) -> None:
        from core.config import Settings
        from core.engine.ai_decision import AIDecisionEngine
        settings = Settings(anthropic_api_key=None)
        engine = AIDecisionEngine(settings)

        result = engine._deterministic_validate({
            "client_name": "Test Client",
            # Missing: target_ips, rules_of_engagement, dll.
        })
        assert result.is_valid is False
        assert len(result.missing_fields) > 0

    def test_parse_json_response_clean(self) -> None:
        from core.config import Settings
        from core.engine.ai_decision import AIDecisionEngine
        settings = Settings(anthropic_api_key=None)
        engine = AIDecisionEngine(settings)

        raw = '{"key": "value", "number": 42}'
        result = engine._parse_json_response(raw)
        assert result["key"] == "value"
        assert result["number"] == 42

    def test_parse_json_response_with_markdown(self) -> None:
        from core.config import Settings
        from core.engine.ai_decision import AIDecisionEngine
        settings = Settings(anthropic_api_key=None)
        engine = AIDecisionEngine(settings)

        raw = '```json\n{"key": "value"}\n```'
        result = engine._parse_json_response(raw)
        assert result["key"] == "value"
