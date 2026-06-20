from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from app.config import DeployWindow, ExchangeTargetConfig, F5TargetConfig, IvantiTargetConfig
from app.targets.base import DeployResult


def _make_mock_target(name: str) -> MagicMock:
    t = MagicMock()
    t.name = name
    t.provider_type = "f5"
    t.deploy.return_value = DeployResult(
        status="ok",
        target=name,
        provider="f5",
        details={"host": f"https://{name}.example.com"},
    )
    return t


def _build_mock_target(cfg: F5TargetConfig) -> MagicMock:
    return _make_mock_target(cfg.name)


class TestBuildTarget:
    def test_build_target_f5(self, tmp_path):
        pw = tmp_path / "pw"
        pw.write_text("secret")
        cfg = F5TargetConfig(
            name="f5-test",
            addr="https://f5.example.com",
            username="admin",
            password_path=str(pw),
            verify=False,
        )
        from app.targets.manager import _build_target

        target = _build_target(cfg)
        from app.targets.f5 import F5Target

        assert isinstance(target, F5Target)
        assert target.name == "f5-test"

    def test_build_target_ivanti(self, tmp_path):
        key = tmp_path / "key"
        key.write_text("sk-ivanti")
        cfg = IvantiTargetConfig(
            name="ivanti-test",
            addr="https://ivanti.example.com",
            api_key_path=str(key),
            verify=False,
        )
        from app.targets.manager import _build_target

        target = _build_target(cfg)
        from app.targets.ivanti import IvantiTarget

        assert isinstance(target, IvantiTarget)
        assert target.name == "ivanti-test"

    def test_build_target_exchange(self, tmp_path):
        pw = tmp_path / "pw"
        pw.write_text("secret")
        cfg = ExchangeTargetConfig(
            name="exchange-test",
            addr="https://exchange.example.com:5986",
            username="DOMAIN\\user",
            password_path=str(pw),
            verify=False,
        )
        from app.targets.manager import _build_target

        target = _build_target(cfg)
        from app.targets.exchange import ExchangeTarget

        assert isinstance(target, ExchangeTarget)
        assert target.name == "exchange-test"

    def test_build_target_unknown_raises(self):
        from app.targets.manager import _build_target

        with pytest.raises(ValueError, match="Unknown target provider"):
            _build_target(MagicMock(provider="unknown"))


class TestDeployManager:
    @pytest.fixture
    def configs(self):
        return [
            F5TargetConfig(
                name="f5-paris",
                addr="https://bigip1.example.com",
                username="admin",
                password_path="/fake/pw",
                verify=False,
            ),
            F5TargetConfig(
                name="f5-london",
                addr="https://bigip2.example.com",
                username="admin",
                password_path="/fake/pw",
                verify=False,
            ),
        ]

    @pytest.fixture
    def manager(self, configs):
        with patch("app.targets.manager._build_target", _build_mock_target):
            from app.targets.manager import DeployManager as DM

            yield DM(configs)

    def test_init_registers_targets(self, manager):
        assert "f5-paris" in manager.targets
        assert "f5-london" in manager.targets
        assert len(manager.targets) == 2

    def test_get_returns_target(self, manager):
        t = manager.get("f5-paris")
        assert t is not None
        assert t.name == "f5-paris"

    def test_get_returns_none_for_unknown(self, manager):
        assert manager.get("nonexistent") is None

    def test_deploy_all_targets(self, manager):
        results = manager.deploy("example.com", "fullchain", "key")
        assert len(results) == 2
        assert all(r.status == "ok" for r in results)

    def test_deploy_subset(self, manager):
        results = manager.deploy("example.com", "fullchain", "key", target_names=["f5-paris"])
        assert len(results) == 1
        assert results[0].target == "f5-paris"

    def test_deploy_empty_subset_raises(self, manager):
        with pytest.raises(KeyError):
            manager.deploy("example.com", "fullchain", "key", target_names=["nonexistent"])

    def test_close_calls_close_on_all(self, manager):
        manager.close()
        for t in manager.targets.values():
            t.close.assert_called_once()

    def test_init_duplicate_name_warns(self, configs):
        dup_configs = configs + [configs[0]]
        with (
            patch("app.targets.manager._build_target", _build_mock_target),
            patch("app.targets.manager.logger") as mock_logger,
        ):
            from app.targets.manager import DeployManager as DM

            DM(dup_configs)
        mock_logger.warning.assert_called_once()

    def test_close_exception_logged(self, manager):
        bad_target = MagicMock()
        bad_target.close.side_effect = RuntimeError("boom")
        manager._targets["bad"] = bad_target
        with patch("app.targets.manager.logger") as mock_logger:
            manager.close()
        mock_logger.exception.assert_called_once()


class TestDeployManagerWindow:
    @pytest.fixture
    def configs(self):
        return [
            F5TargetConfig(
                name="f5-paris",
                addr="https://bigip1.example.com",
                username="admin",
                password_path="/fake/pw",
                verify=False,
                deploy_window=DeployWindow(
                    start="08:00",
                    end="18:00",
                    days=[1, 2, 3, 4, 5],
                ),
            ),
            F5TargetConfig(
                name="f5-london",
                addr="https://bigip2.example.com",
                username="admin",
                password_path="/fake/pw",
                verify=False,
            ),
        ]

    @pytest.fixture
    def manager(self, configs):
        with patch("app.targets.manager._build_target", _build_mock_target):
            from app.targets.manager import DeployManager as DM

            yield DM(configs)

    def test_deferred_outside_window(self, manager):
        """Target with window outside hours returns deferred."""
        with patch("app.targets.manager.is_within_window", return_value=False), patch("app.targets.manager.next_window_start") as mock_next:
            mock_next.return_value = datetime(2026, 6, 22, 8, 0, tzinfo=UTC)
            results = manager.deploy("example.com", "fullchain", "key")
            assert results[0].status == "deferred"
            assert results[0].details["next_window"] == "2026-06-22T08:00:00+00:00"

    def test_immediate_within_window(self, manager):
        """Target with window within hours deploys immediately."""
        with patch("app.targets.manager.is_within_window", return_value=True):
            results = manager.deploy("example.com", "fullchain", "key")
            assert results[0].status == "ok"

    def test_without_window_deploys_immediately(self, manager):
        """Target without deploy_window always deploys."""
        assert manager._windows["f5-london"] is None
        results = manager.deploy("example.com", "fullchain", "key", target_names=["f5-london"])
        assert results[0].status == "ok"

    def test_default_window_from_global(self):
        """Target without own window inherits global default."""
        cfg = F5TargetConfig(
            name="f5-paris",
            addr="https://bigip1.example.com",
            username="admin",
            password_path="/fake/pw",
            verify=False,
        )
        global_win = DeployWindow(start="08:00", end="18:00", days=[1, 2, 3, 4, 5])
        with patch("app.targets.manager._build_target", _build_mock_target):
            from app.targets.manager import DeployManager as DM

            mgr = DM([cfg], default_window=global_win)
        assert mgr._windows["f5-paris"] is global_win

    def test_per_target_window_overrides_global(self):
        """Target with explicit window ignores global default."""
        cfg = F5TargetConfig(
            name="f5-paris",
            addr="https://bigip1.example.com",
            username="admin",
            password_path="/fake/pw",
            verify=False,
            deploy_window=DeployWindow(start="22:00", end="06:00"),
        )
        global_win = DeployWindow(start="08:00", end="18:00", days=[1, 2, 3, 4, 5])
        with patch("app.targets.manager._build_target", _build_mock_target):
            from app.targets.manager import DeployManager as DM

            mgr = DM([cfg], default_window=global_win)
        assert mgr._windows["f5-paris"] is cfg.deploy_window

    def test_scheduler_shuts_down_on_close(self, manager):
        manager.close()
        assert not manager._scheduler.running
