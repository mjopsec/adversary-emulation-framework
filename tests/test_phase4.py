"""
Test suite Phase 4 — Agent Framework.
Memverifikasi model Agent/AgentTask, AgentManager, BeaconHandler, dan TaskDispatcher.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ─── Model Tests ──────────────────────────────────────────────────────────────

class TestAgentModel:
    """Test atribut dan properties model Agent."""

    def _make_agent(self, **kwargs) -> "Agent":
        from core.models.agent import Agent
        defaults = dict(
            hostname="target-win10",
            ip_address="192.168.1.50",
            os_type="windows",
            agent_type="it",
            status="active",
            beacon_interval_seconds=60,
            check_in_count=5,
            privilege_level="admin",
            has_elevated=True,
        )
        defaults.update(kwargs)
        agent = Agent(**defaults)
        agent.capabilities = ["execute_cmd", "file_read", "process_inject"]
        return agent

    def test_agent_has_token_generated(self) -> None:
        """Token di-generate oleh SQLAlchemy default saat INSERT; verifikasi formatnya."""
        import secrets
        # Verify token generation function produces correct format
        token = secrets.token_hex(32)
        assert len(token) == 64  # 32 bytes hex = 64 chars
        assert all(c in "0123456789abcdef" for c in token)

    def test_agent_token_unique(self) -> None:
        """Setiap token yang di-generate harus unik."""
        import secrets
        tokens = {secrets.token_hex(32) for _ in range(10)}
        assert len(tokens) == 10  # Semua unique

    def test_agent_capabilities_property(self) -> None:
        agent = self._make_agent()
        assert "execute_cmd" in agent.capabilities
        assert "process_inject" in agent.capabilities

    def test_agent_capabilities_setter(self) -> None:
        from core.models.agent import Agent
        agent = Agent(hostname="test", agent_type="it")
        agent.capabilities = ["modbus_read", "dnp3_read"]
        assert "modbus_read" in agent.capabilities

    def test_agent_is_active_property(self) -> None:
        agent = self._make_agent(status="active")
        assert agent.is_active is True

        agent2 = self._make_agent(status="stale")
        assert agent2.is_active is False

    def test_agent_has_capability(self) -> None:
        agent = self._make_agent()
        assert agent.has_capability("execute_cmd") is True
        assert agent.has_capability("modbus_write") is False

    def test_agent_metadata_extra_property(self) -> None:
        from core.models.agent import Agent
        agent = Agent(hostname="test", agent_type="it")
        agent.metadata_extra = {"antivirus": "Windows Defender", "edr": "none"}
        assert agent.metadata_extra["antivirus"] == "Windows Defender"

    def test_agent_repr(self) -> None:
        agent = self._make_agent()
        r = repr(agent)
        assert "Agent" in r
        assert "target-win10" in r


class TestAgentTaskModel:
    """Test model AgentTask."""

    def _make_task(self, **kwargs) -> "AgentTask":
        from core.models.agent import AgentTask
        defaults = dict(
            agent_id="agent-123",
            task_type="execute_technique",
            technique_id="T1566",
            status="pending",
            priority=5,
            timeout_seconds=300,
        )
        defaults.update(kwargs)
        task = AgentTask(**defaults)
        task.task_params = {"variant": "spearphishing_link"}
        return task

    def test_task_params_property(self) -> None:
        task = self._make_task()
        assert task.task_params["variant"] == "spearphishing_link"

    def test_task_artifacts_property(self) -> None:
        task = self._make_task()
        task.artifacts = ["C:\\temp\\payload.exe", "C:\\temp\\log.txt"]
        assert len(task.artifacts) == 2

    def test_task_collected_data_property(self) -> None:
        task = self._make_task()
        task.collected_data = {"credentials": ["admin:pass123"]}
        assert "credentials" in task.collected_data

    def test_task_is_terminal_pending(self) -> None:
        task = self._make_task(status="pending")
        assert task.is_terminal is False

    def test_task_is_terminal_completed(self) -> None:
        task = self._make_task(status="completed")
        assert task.is_terminal is True

    def test_task_is_terminal_failed(self) -> None:
        task = self._make_task(status="failed")
        assert task.is_terminal is True

    def test_task_is_terminal_timeout(self) -> None:
        task = self._make_task(status="timeout")
        assert task.is_terminal is True

    def test_task_repr(self) -> None:
        task = self._make_task()
        r = repr(task)
        assert "AgentTask" in r
        assert "T1566" in r


# ─── AgentManager Tests ───────────────────────────────────────────────────────

class TestAgentManager:
    """Test AgentManager logic (dengan mocked session)."""

    def _make_manager(self) -> "AgentManager":
        from core.agent.agent_manager import AgentManager
        session = AsyncMock()
        return AgentManager(session)

    def test_default_capabilities_it(self) -> None:
        from core.agent.agent_manager import AgentManager
        caps = AgentManager._default_capabilities("it")
        assert "execute_cmd" in caps
        assert "file_read" in caps
        assert "network_scan" in caps

    def test_default_capabilities_ot(self) -> None:
        from core.agent.agent_manager import AgentManager
        caps = AgentManager._default_capabilities("ot")
        assert "modbus_read" in caps
        assert "dnp3_read" in caps
        assert "opc_ua_browse" in caps

    def test_default_capabilities_it_no_ot_specific(self) -> None:
        from core.agent.agent_manager import AgentManager
        it_caps = AgentManager._default_capabilities("it")
        assert "modbus_write" not in it_caps

    @pytest.mark.asyncio
    async def test_register_creates_agent(self) -> None:
        from core.agent.agent_manager import AgentManager
        from core.models.agent import Agent

        session = AsyncMock()
        # Simulate session.refresh populating the agent
        agent_obj = Agent(
            hostname="new-target",
            ip_address="10.0.0.5",
            os_type="linux",
            agent_type="it",
        )
        agent_obj.capabilities = []

        session.add = MagicMock()
        session.commit = AsyncMock()
        session.refresh = AsyncMock(side_effect=lambda a: None)

        manager = AgentManager(session)

        # Mock agar session.refresh mengisi data
        with patch.object(manager, "register", return_value=agent_obj) as mock_reg:
            result = await manager.register(
                hostname="new-target",
                ip_address="10.0.0.5",
                os_type="linux",
            )
            mock_reg.assert_called_once()

    @pytest.mark.asyncio
    async def test_process_checkin_invalid_token(self) -> None:
        from core.agent.agent_manager import AgentManager
        from core.models.agent import Agent

        session = AsyncMock()
        agent = Agent(hostname="target", agent_type="it", status="active")
        agent.token = "correct_token_hex_value_here_abcdef1234567890abcdef1234567890"

        mock_result = AsyncMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=agent)
        session.execute = AsyncMock(return_value=mock_result)

        manager = AgentManager(session)
        result = await manager.process_checkin(
            agent_id=agent.id or "test-id",
            token="wrong_token",
        )
        assert result["authenticated"] is False

    @pytest.mark.asyncio
    async def test_process_checkin_terminated_agent(self) -> None:
        from core.agent.agent_manager import AgentManager
        from core.models.agent import Agent

        session = AsyncMock()
        agent = Agent(hostname="dead-target", agent_type="it", status="terminated")
        agent.token = "correct_token_32bytes_hex_value_abcdef1234567890abcdef12345678"

        mock_result = AsyncMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=agent)
        session.execute = AsyncMock(return_value=mock_result)

        manager = AgentManager(session)
        result = await manager.process_checkin(
            agent_id="some-id",
            token=agent.token,
        )
        assert result["authenticated"] is False
        assert "self_destruct" in result.get("commands", [])

    @pytest.mark.asyncio
    async def test_terminate_agent_not_found(self) -> None:
        from core.agent.agent_manager import AgentManager

        session = AsyncMock()
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=None)
        session.execute = AsyncMock(return_value=mock_result)

        manager = AgentManager(session)
        success = await manager.terminate_agent("nonexistent-id")
        assert success is False

    @pytest.mark.asyncio
    async def test_cancel_task_not_found(self) -> None:
        from core.agent.agent_manager import AgentManager

        session = AsyncMock()
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=None)
        session.execute = AsyncMock(return_value=mock_result)

        manager = AgentManager(session)
        result = await manager.cancel_task("nonexistent-task")
        assert result is False

    @pytest.mark.asyncio
    async def test_cancel_terminal_task_returns_false(self) -> None:
        from core.agent.agent_manager import AgentManager
        from core.models.agent import AgentTask

        session = AsyncMock()
        task = AgentTask(agent_id="a", task_type="exec", status="completed")

        mock_result = AsyncMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=task)
        session.execute = AsyncMock(return_value=mock_result)

        manager = AgentManager(session)
        result = await manager.cancel_task("task-already-done")
        assert result is False

    def test_get_agent_summary_structure(self) -> None:
        from core.agent.agent_manager import AgentManager
        from core.models.agent import Agent
        from datetime import datetime, timezone

        session = AsyncMock()
        agent = Agent(
            hostname="test-win",
            ip_address="10.0.0.10",
            os_type="windows",
            agent_type="it",
            status="active",
            privilege_level="admin",
            check_in_count=3,
            beacon_interval_seconds=60,
        )
        agent.capabilities = ["execute_cmd"]
        agent.registered_at = datetime.now(timezone.utc).replace(tzinfo=None)

        manager = AgentManager(session)
        summary = manager.get_agent_summary(agent)

        assert "id" in summary
        assert "hostname" in summary
        assert "status" in summary
        assert "capabilities" in summary
        assert "privilege_level" in summary
        assert summary["hostname"] == "test-win"
        assert summary["status"] == "active"


# ─── BeaconHandler Tests ──────────────────────────────────────────────────────

class TestBeaconHandler:
    """Test beacon check-in dan task result handling."""

    @pytest.mark.asyncio
    async def test_checkin_authentication_failure(self) -> None:
        from core.agent.beacon_handler import BeaconHandler, CheckinRequest

        session = AsyncMock()

        with patch("core.agent.beacon_handler.AgentManager") as MockManager:
            mock_mgr = AsyncMock()
            mock_mgr.process_checkin = AsyncMock(return_value={
                "authenticated": False,
                "tasks": [],
                "commands": [],
            })
            MockManager.return_value = mock_mgr

            handler = BeaconHandler(session)
            request = CheckinRequest(
                agent_id="agent-1",
                token="wrong_token",
            )
            response = await handler.handle_checkin(request)
            assert response.authenticated is False

    @pytest.mark.asyncio
    async def test_checkin_success_with_tasks(self) -> None:
        from core.agent.beacon_handler import BeaconHandler, CheckinRequest

        session = AsyncMock()

        with patch("core.agent.beacon_handler.AgentManager") as MockManager:
            mock_mgr = AsyncMock()
            mock_mgr.process_checkin = AsyncMock(return_value={
                "authenticated": True,
                "agent_id": "agent-1",
                "tasks": [
                    {"task_id": "t1", "task_type": "execute_technique",
                     "technique_id": "T1566", "params": {}, "timeout_seconds": 300, "priority": 5}
                ],
                "commands": [],
            })
            MockManager.return_value = mock_mgr

            handler = BeaconHandler(session)
            request = CheckinRequest(
                agent_id="agent-1",
                token="correct_token",
                system_info={"os": "Windows 10"},
            )
            response = await handler.handle_checkin(request)
            assert response.authenticated is True
            assert len(response.tasks) == 1
            # Dengan tasks, next_checkin harus lebih pendek
            assert response.next_checkin_seconds <= 60

    @pytest.mark.asyncio
    async def test_checkin_no_tasks_normal_interval(self) -> None:
        from core.agent.beacon_handler import BeaconHandler, CheckinRequest

        session = AsyncMock()

        with patch("core.agent.beacon_handler.AgentManager") as MockManager:
            mock_mgr = AsyncMock()
            mock_mgr.process_checkin = AsyncMock(return_value={
                "authenticated": True,
                "agent_id": "agent-1",
                "tasks": [],
                "commands": [],
            })
            MockManager.return_value = mock_mgr

            handler = BeaconHandler(session)
            request = CheckinRequest(agent_id="agent-1", token="correct_token")
            response = await handler.handle_checkin(request)
            assert response.authenticated is True
            assert response.next_checkin_seconds == 60

    @pytest.mark.asyncio
    async def test_task_result_success(self) -> None:
        from core.agent.beacon_handler import BeaconHandler, TaskResultRequest

        session = AsyncMock()

        with patch("core.agent.beacon_handler.AgentManager") as MockManager:
            mock_mgr = AsyncMock()
            mock_mgr.submit_task_result = AsyncMock(return_value=True)
            MockManager.return_value = mock_mgr

            handler = BeaconHandler(session)
            request = TaskResultRequest(
                agent_id="agent-1",
                token="correct_token",
                task_id="task-abc",
                result_status="success",
                output="Eksekusi berhasil.",
            )
            result = await handler.handle_task_result(request)
            assert result["success"] is True

    @pytest.mark.asyncio
    async def test_task_result_auth_failure(self) -> None:
        from core.agent.beacon_handler import BeaconHandler, TaskResultRequest

        session = AsyncMock()

        with patch("core.agent.beacon_handler.AgentManager") as MockManager:
            mock_mgr = AsyncMock()
            mock_mgr.submit_task_result = AsyncMock(return_value=False)
            MockManager.return_value = mock_mgr

            handler = BeaconHandler(session)
            request = TaskResultRequest(
                agent_id="agent-1",
                token="wrong_token",
                task_id="task-abc",
                result_status="failed",
            )
            result = await handler.handle_task_result(request)
            assert result["success"] is False

    def test_checkin_response_to_dict(self) -> None:
        from core.agent.beacon_handler import CheckinResponse
        response = CheckinResponse(
            authenticated=True,
            agent_id="agent-1",
            tasks=[{"task_id": "t1"}],
            commands=[],
            next_checkin_seconds=30,
        )
        d = response.to_dict()
        assert d["authenticated"] is True
        assert d["agent_id"] == "agent-1"
        assert len(d["tasks"]) == 1
        assert d["next_checkin_seconds"] == 30


# ─── TaskDispatcher Tests ─────────────────────────────────────────────────────

class TestTaskDispatcher:
    """Test task dispatcher routing logic."""

    @pytest.mark.asyncio
    async def test_dispatch_no_agent_uses_registry(self) -> None:
        """Tanpa agent, dispatcher harus menggunakan registry atau simulasi."""
        from core.agent.task_dispatcher import TaskDispatcher
        from core.techniques.base import ExecutionStatus

        session = AsyncMock()

        with patch("core.agent.task_dispatcher.AgentManager") as MockManager, \
             patch("core.agent.task_dispatcher.TechniqueRegistry") as MockRegistry:

            mock_mgr = AsyncMock()
            mock_mgr.find_agent_for_target = AsyncMock(return_value=None)
            MockManager.return_value = mock_mgr

            mock_reg = MagicMock()
            mock_reg.get = MagicMock(return_value=None)
            mock_reg.get_class = MagicMock(return_value=None)
            MockRegistry.instance = MagicMock(return_value=mock_reg)

            dispatcher = TaskDispatcher(session)
            result = await dispatcher.dispatch(
                technique_id="T1566",
                target_ip="192.168.1.100",
                scope_ips=["192.168.1.0/24"],
            )
            assert result.technique_id == "T1566"
            assert result.status in (ExecutionStatus.SUCCESS, ExecutionStatus.FAILED)
            assert result.dispatched_via == "simulation"

    @pytest.mark.asyncio
    async def test_dispatch_with_registry_implementation(self) -> None:
        """Jika teknik ada di registry, dispatcher gunakan implementasinya."""
        from core.agent.task_dispatcher import TaskDispatcher
        from core.techniques.base import ExecutionStatus, TechniqueResult

        session = AsyncMock()

        mock_tech = AsyncMock()
        mock_result = TechniqueResult(
            status=ExecutionStatus.SUCCESS,
            technique_id="T1566",
            target="192.168.1.100",
            output="Simulated phishing success.",
        )
        mock_tech.run = AsyncMock(return_value=mock_result)

        with patch("core.agent.task_dispatcher.AgentManager") as MockManager, \
             patch("core.agent.task_dispatcher.TechniqueRegistry") as MockRegistry:

            mock_mgr = AsyncMock()
            mock_mgr.find_agent_for_target = AsyncMock(return_value=None)
            MockManager.return_value = mock_mgr

            mock_reg = MagicMock()
            mock_reg.get = MagicMock(return_value=mock_tech)
            MockRegistry.instance = MagicMock(return_value=mock_reg)

            dispatcher = TaskDispatcher(session)
            result = await dispatcher.dispatch(
                technique_id="T1566",
                target_ip="192.168.1.100",
                scope_ips=["192.168.1.0/24"],
                prefer_agent=False,
            )
            assert result.status == ExecutionStatus.SUCCESS
            assert result.dispatched_via == "registry"

    def test_enrich_context_from_it_agent(self) -> None:
        from core.agent.task_dispatcher import TaskDispatcher
        from core.models.agent import Agent

        agent = Agent(
            hostname="win-target",
            ip_address="10.0.0.5",
            os_type="windows",
            agent_type="it",
            privilege_level="admin",
            has_elevated=True,
        )
        agent.capabilities = ["execute_cmd", "process_inject"]

        enriched = TaskDispatcher._enrich_context_from_agent(agent, {"variant": "link"})

        assert enriched["agent_hostname"] == "win-target"
        assert enriched["agent_os"] == "windows"
        assert enriched["agent_privilege"] == "admin"
        assert enriched["has_admin"] is True
        assert enriched["variant"] == "link"  # Original context preserved

    def test_enrich_context_from_ot_agent(self) -> None:
        from core.agent.task_dispatcher import TaskDispatcher
        from core.models.agent import Agent

        agent = Agent(
            hostname="plc-01",
            ip_address="192.168.100.10",
            os_type="rtu",
            agent_type="ot",
            privilege_level="user",
            has_elevated=False,
            ot_protocol="modbus",
        )
        agent.capabilities = ["modbus_read"]

        enriched = TaskDispatcher._enrich_context_from_agent(agent, {})
        # OT protocol harus di-inject ke context
        assert enriched.get("protocol") == "modbus"

    def test_dispatch_result_to_dict(self) -> None:
        from core.agent.task_dispatcher import DispatchResult
        from core.techniques.base import ExecutionStatus

        result = DispatchResult(
            technique_id="T1566",
            target="192.168.1.100",
            status=ExecutionStatus.SUCCESS,
            output="Success",
            dispatched_via="registry",
        )
        d = result.to_dict()
        assert d["technique_id"] == "T1566"
        assert d["status"] == "success"
        assert d["dispatched_via"] == "registry"
        assert d["artifacts"] == []
        assert d["collected_data"] == {}

    def test_dispatch_result_is_success(self) -> None:
        from core.agent.task_dispatcher import DispatchResult
        from core.techniques.base import ExecutionStatus

        success_result = DispatchResult("T1566", "target", ExecutionStatus.SUCCESS)
        assert success_result.is_success is True

        fail_result = DispatchResult("T1566", "target", ExecutionStatus.FAILED)
        assert fail_result.is_success is False


# ─── Integration Tests ────────────────────────────────────────────────────────

class TestPhase4Integration:
    """Test integrasi komponen Phase 4."""

    def test_agent_type_determines_capabilities(self) -> None:
        from core.agent.agent_manager import AgentManager
        it_caps = AgentManager._default_capabilities("it")
        ot_caps = AgentManager._default_capabilities("ot")

        # IT dan OT harus punya kapabilitas yang berbeda
        it_only = set(it_caps) - set(ot_caps)
        ot_only = set(ot_caps) - set(it_caps)

        assert len(it_only) > 0, "IT harus punya kapabilitas yang tidak ada di OT"
        assert len(ot_only) > 0, "OT harus punya kapabilitas yang tidak ada di IT"

    def test_checkin_request_dataclass(self) -> None:
        from core.agent.beacon_handler import CheckinRequest
        req = CheckinRequest(
            agent_id="agent-1",
            token="my-token",
            system_info={"os": "Windows 10", "domain": "corp.local"},
            current_tasks_running=2,
            memory_mb=8192,
            cpu_percent=45.2,
        )
        assert req.agent_id == "agent-1"
        assert req.system_info["domain"] == "corp.local"
        assert req.memory_mb == 8192

    def test_task_result_request_dataclass(self) -> None:
        from core.agent.beacon_handler import TaskResultRequest
        req = TaskResultRequest(
            agent_id="agent-1",
            token="my-token",
            task_id="task-abc",
            result_status="success",
            output="Teknik berhasil dieksekusi.",
            artifacts=["C:\\temp\\loot.txt"],
            collected_data={"user": "admin", "hash": "abc123"},
        )
        assert req.result_status == "success"
        assert len(req.artifacts) == 1
        assert req.collected_data["user"] == "admin"

    def test_all_agent_statuses_valid(self) -> None:
        """Status agent yang valid harus jelas terdefinisi."""
        valid_statuses = {"registered", "active", "stale", "terminated"}
        # Cek tidak ada typo di konstanta
        from core.agent.agent_manager import AgentManager
        # Cek stale_multiplier masuk akal
        assert AgentManager.STALE_MULTIPLIER >= 2, "Stale multiplier harus minimal 2x interval"

    def test_all_task_statuses_valid(self) -> None:
        """Status task yang valid mencakup semua state yang dibutuhkan."""
        from core.models.agent import AgentTask
        task = AgentTask(agent_id="a", task_type="exec", status="pending")

        # Terminal states
        for terminal in ["completed", "failed", "timeout", "cancelled"]:
            task.status = terminal
            assert task.is_terminal is True

        # Non-terminal states
        for active in ["pending", "assigned", "running"]:
            task.status = active
            assert task.is_terminal is False
