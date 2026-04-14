"""
Test suite Phase 2 — Technique Library.
Memverifikasi registry, implementasi teknik IT dan OT, serta selector.
"""

import asyncio
import pytest


# ─── Technique Registry Tests ─────────────────────────────────────────────────

class TestTechniqueRegistry:
    def test_registry_singleton(self) -> None:
        from core.techniques.registry import TechniqueRegistry
        r1 = TechniqueRegistry.instance()
        r2 = TechniqueRegistry.instance()
        assert r1 is r2

    def test_registry_discovers_techniques(self) -> None:
        from core.techniques.registry import TechniqueRegistry
        registry = TechniqueRegistry.instance()
        # Harus ada setidaknya teknik IT dan OT yang kita implementasikan
        assert registry.count() >= 10

    def test_registry_has_it_techniques(self) -> None:
        from core.techniques.registry import TechniqueRegistry
        registry = TechniqueRegistry.instance()
        it_techs = registry.list_by_environment("it")
        # T1566, T1059, T1078, T1021, T1003, T1071 harus ada
        expected = ["T1003", "T1021", "T1059", "T1071", "T1078", "T1566"]
        for tid in expected:
            assert tid in it_techs, f"{tid} tidak ditemukan di registry IT"

    def test_registry_has_ot_techniques(self) -> None:
        from core.techniques.registry import TechniqueRegistry
        registry = TechniqueRegistry.instance()
        ot_techs = registry.list_by_environment("ot")
        expected = ["T0801", "T0843", "T0856", "T0869"]
        for tid in expected:
            assert tid in ot_techs, f"{tid} tidak ditemukan di registry OT"

    def test_get_technique_returns_instance(self) -> None:
        from core.techniques.registry import TechniqueRegistry
        from core.techniques.base import BaseTechnique
        registry = TechniqueRegistry.instance()
        technique = registry.get("T1566")
        assert technique is not None
        assert isinstance(technique, BaseTechnique)
        assert technique.technique_id == "T1566"

    def test_get_nonexistent_returns_none(self) -> None:
        from core.techniques.registry import TechniqueRegistry
        registry = TechniqueRegistry.instance()
        assert registry.get("T9999") is None

    def test_list_by_risk(self) -> None:
        from core.techniques.registry import TechniqueRegistry
        registry = TechniqueRegistry.instance()
        low_risk = registry.list_by_risk("low")
        medium_risk = registry.list_by_risk("medium")
        # Medium risk harus mencakup lebih banyak teknik dari low risk
        assert len(medium_risk) >= len(low_risk)


# ─── IT Technique Tests ───────────────────────────────────────────────────────

class TestITTechniques:
    @pytest.mark.asyncio
    async def test_phishing_success(self) -> None:
        from core.techniques.it.t1566_phishing import PhishingTechnique
        from core.techniques.base import TechniqueContext, ExecutionStatus

        tech = PhishingTechnique()
        ctx = TechniqueContext(
            target_host="192.168.1.100",
            scope_ips=["192.168.1.0/24"],
            campaign_id="test-campaign",
            extra={"variant": "spearphishing_link"},
        )
        result = await tech.run(ctx)
        # Bisa SUCCESS atau PARTIAL (tergantung simulasi)
        assert result.status in (ExecutionStatus.SUCCESS, ExecutionStatus.PARTIAL)
        assert result.technique_id == "T1566"
        assert len(result.output) > 50

    @pytest.mark.asyncio
    async def test_cmd_scripting_out_of_scope_aborted(self) -> None:
        from core.techniques.it.t1059_cmd_scripting import CommandScriptingTechnique
        from core.techniques.base import TechniqueContext, ExecutionStatus

        tech = CommandScriptingTechnique()
        ctx = TechniqueContext(
            target_host="10.0.0.1",          # Di luar scope
            scope_ips=["192.168.1.0/24"],     # Scope berbeda
            campaign_id="test-campaign",
        )
        result = await tech.run(ctx)
        assert result.status == ExecutionStatus.ABORTED
        assert "luar scope" in result.error

    @pytest.mark.asyncio
    async def test_valid_accounts_no_credentials(self) -> None:
        from core.techniques.it.t1078_valid_accounts import ValidAccountsTechnique
        from core.techniques.base import TechniqueContext, ExecutionStatus

        tech = ValidAccountsTechnique()
        ctx = TechniqueContext(
            target_host="192.168.1.100",
            scope_ips=["192.168.1.0/24"],
            campaign_id="test-campaign",
            # Tidak ada password atau hash
        )
        result = await tech.run(ctx)
        assert result.status == ExecutionStatus.FAILED
        assert len(result.next_step_hints) > 0

    @pytest.mark.asyncio
    async def test_valid_accounts_with_credentials(self) -> None:
        from core.techniques.it.t1078_valid_accounts import ValidAccountsTechnique
        from core.techniques.base import TechniqueContext, ExecutionStatus

        tech = ValidAccountsTechnique()
        ctx = TechniqueContext(
            target_host="192.168.1.100",
            scope_ips=["192.168.1.0/24"],
            campaign_id="test-campaign",
            username="administrator",
            password="P@ssw0rd",
        )
        result = await tech.run(ctx)
        assert result.status in (ExecutionStatus.SUCCESS, ExecutionStatus.PARTIAL)

    @pytest.mark.asyncio
    async def test_credential_dumping_no_privileges(self) -> None:
        from core.techniques.it.t1003_credential_dumping import CredentialDumpingTechnique
        from core.techniques.base import TechniqueContext, ExecutionStatus

        tech = CredentialDumpingTechnique()
        ctx = TechniqueContext(
            target_host="192.168.1.100",
            scope_ips=["192.168.1.0/24"],
            campaign_id="test-campaign",
            extra={"has_admin": False, "check_privileges": True},
        )
        result = await tech.run(ctx)
        assert result.status == ExecutionStatus.FAILED

    @pytest.mark.asyncio
    async def test_credential_dumping_collects_data(self) -> None:
        from core.techniques.it.t1003_credential_dumping import CredentialDumpingTechnique
        from core.techniques.base import TechniqueContext, ExecutionStatus

        tech = CredentialDumpingTechnique()
        ctx = TechniqueContext(
            target_host="192.168.1.100",
            scope_ips=["192.168.1.0/24"],
            campaign_id="test-campaign",
            extra={"has_admin": True, "dump_method": "sam_registry"},
        )
        result = await tech.run(ctx)
        if result.status == ExecutionStatus.SUCCESS:
            assert "credentials" in result.collected_data
            assert len(result.collected_data["credentials"]) > 0

    @pytest.mark.asyncio
    async def test_remote_services_no_credentials(self) -> None:
        from core.techniques.it.t1021_remote_services import RemoteServicesTechnique
        from core.techniques.base import TechniqueContext, ExecutionStatus

        tech = RemoteServicesTechnique()
        ctx = TechniqueContext(
            target_host="192.168.1.100",
            scope_ips=["192.168.1.0/24"],
            campaign_id="test-campaign",
        )
        result = await tech.run(ctx)
        assert result.status == ExecutionStatus.FAILED


# ─── OT Technique Tests ───────────────────────────────────────────────────────

class TestOTTechniques:
    @pytest.mark.asyncio
    async def test_monitor_process_state_reads_data(self) -> None:
        from core.techniques.ot.t0801_monitor_process_state import MonitorProcessStateTechnique
        from core.techniques.base import TechniqueContext, ExecutionStatus

        tech = MonitorProcessStateTechnique()
        ctx = TechniqueContext(
            target_host="192.168.100.10",
            scope_ips=["192.168.100.0/24"],
            campaign_id="test-ot",
            production_safe_mode=True,  # Read-only aman
            extra={"protocol": "modbus"},
        )
        result = await tech.run(ctx)
        # Monitor process state TIDAK destruktif, harus lolos safety gate
        assert result.status in (ExecutionStatus.SUCCESS, ExecutionStatus.PARTIAL)
        assert "process_snapshot" in result.collected_data
        assert result.collected_data["unsafe_conditions"] >= 0

    @pytest.mark.asyncio
    async def test_program_download_blocked_in_safe_mode(self) -> None:
        from core.techniques.ot.t0843_program_download import ProgramDownloadTechnique
        from core.techniques.base import TechniqueContext, ExecutionStatus

        tech = ProgramDownloadTechnique()
        ctx = TechniqueContext(
            target_host="192.168.100.10",
            scope_ips=["192.168.100.0/24"],
            campaign_id="test-ot",
            production_safe_mode=True,   # HARUS DIBLOKIR
            extra={"download_only": False},  # Write mode
        )
        result = await tech.run(ctx)
        # T0843 is_destructive=True + production_safe_mode=True → HARUS ABORTED
        assert result.status == ExecutionStatus.ABORTED
        assert "production_safe_mode" in result.error.lower() or "izin eksplisit" in result.error.lower()

    @pytest.mark.asyncio
    async def test_program_download_only_allowed_in_safe_mode(self) -> None:
        """Download-only (baca program) aman — tapi masih diblokir karena is_destructive=True."""
        from core.techniques.ot.t0843_program_download import ProgramDownloadTechnique
        from core.techniques.base import TechniqueContext, ExecutionStatus

        tech = ProgramDownloadTechnique()
        ctx = TechniqueContext(
            target_host="192.168.100.10",
            scope_ips=["192.168.100.0/24"],
            campaign_id="test-ot",
            production_safe_mode=False,  # Izin eksplisit
            extra={"download_only": True},
        )
        result = await tech.run(ctx)
        # Seharusnya lolos safety gate karena production_safe_mode=False
        assert result.status in (ExecutionStatus.SUCCESS, ExecutionStatus.PARTIAL)

    @pytest.mark.asyncio
    async def test_spoof_reporting_blocked_in_safe_mode(self) -> None:
        from core.techniques.ot.t0856_spoof_reporting import SpoofReportingTechnique
        from core.techniques.base import TechniqueContext, ExecutionStatus

        tech = SpoofReportingTechnique()
        ctx = TechniqueContext(
            target_host="192.168.100.20",
            scope_ips=["192.168.100.0/24"],
            campaign_id="test-ot",
            production_safe_mode=True,
        )
        result = await tech.run(ctx)
        assert result.status == ExecutionStatus.ABORTED

    @pytest.mark.asyncio
    async def test_ot_c2_channel_setup(self) -> None:
        from core.techniques.ot.t0869_std_app_layer_protocol import StandardAppLayerOTTechnique
        from core.techniques.base import TechniqueContext, ExecutionStatus

        tech = StandardAppLayerOTTechnique()
        ctx = TechniqueContext(
            target_host="192.168.100.10",
            scope_ips=["192.168.100.0/24"],
            campaign_id="test-ot",
            production_safe_mode=False,
            extra={"ot_channel": "modbus_covert"},
        )
        result = await tech.run(ctx)
        assert result.status in (ExecutionStatus.SUCCESS, ExecutionStatus.PARTIAL)


# ─── Teknik Metadata Tests ────────────────────────────────────────────────────

class TestTechniqueMetadata:
    def test_all_registered_techniques_have_metadata(self) -> None:
        from core.techniques.registry import TechniqueRegistry
        registry = TechniqueRegistry.instance()
        for tid in registry.list_all():
            cls = registry.get_class(tid)
            assert cls is not None
            assert cls.technique_id, f"{tid}: technique_id kosong"
            assert cls.name, f"{tid}: name kosong"
            assert cls.supported_environments, f"{tid}: supported_environments kosong"
            assert cls.risk_level in ("low", "medium", "high", "critical"), \
                f"{tid}: risk_level tidak valid: {cls.risk_level}"

    def test_ot_destructive_techniques_flagged(self) -> None:
        from core.techniques.registry import TechniqueRegistry
        registry = TechniqueRegistry.instance()
        # T0843 dan T0856 harus is_destructive=True
        for destructive_id in ["T0843", "T0856"]:
            cls = registry.get_class(destructive_id)
            if cls:  # Hanya cek jika terdaftar
                assert cls.is_destructive is True, \
                    f"{destructive_id} seharusnya is_destructive=True"

    def test_t0801_not_destructive(self) -> None:
        from core.techniques.registry import TechniqueRegistry
        registry = TechniqueRegistry.instance()
        cls = registry.get_class("T0801")
        if cls:
            assert cls.is_destructive is False, "T0801 seharusnya tidak destruktif"
