from unittest.mock import MagicMock, patch

import pytest

from app.config import F5TargetConfig
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
