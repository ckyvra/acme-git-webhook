import yaml
import pytest
from pydantic import ValidationError

from app.config import load_config, AppConfig, AuthConfig, WebhookConfig, RepoConfig


class TestAuthConfig:
    def test_valid(self):
        cfg = AuthConfig(api_keys=["key1", "key2"])
        assert cfg.api_keys == ["key1", "key2"]

    def test_empty_keys(self):
        cfg = AuthConfig(api_keys=[])
        assert cfg.api_keys == []


class TestWebhookConfig:
    def test_defaults(self):
        cfg = WebhookConfig()
        assert cfg.bind == "0.0.0.0:8000"
        assert cfg.work_dir == "/data/acme-git-webhook"
        assert cfg.ssh_key is None

    def test_custom(self):
        cfg = WebhookConfig(bind="127.0.0.1:9000", work_dir="/tmp/test", ssh_key="/key")
        assert cfg.bind == "127.0.0.1:9000"
        assert cfg.ssh_key == "/key"


class TestRepoConfig:
    def test_defaults(self):
        cfg = RepoConfig(url="git@github.com:org/dns-zones.git")
        assert cfg.branch == "main"
        assert cfg.zone_path == "."
        assert cfg.zone_file_suffix == ".zone"

    def test_custom(self):
        cfg = RepoConfig(
            url="git@example.com:repo.git",
            branch="develop",
            zone_path="bind/zones",
            zone_file_suffix=".db",
        )
        assert cfg.zone_path == "bind/zones"
        assert cfg.zone_file_suffix == ".db"


class TestAppConfig:
    def test_valid(self):
        cfg = AppConfig(
            auth=AuthConfig(api_keys=["k"]),
            webhook=WebhookConfig(),
            repo=RepoConfig(url="git@github.com:org/dns-zones.git"),
        )
        assert cfg.auth.api_keys == ["k"]

    def test_missing_field(self):
        with pytest.raises(ValidationError):
            AppConfig(auth=AuthConfig(api_keys=["k"]), webhook=WebhookConfig())


class TestLoadConfig:
    def test_load_valid(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text(
            yaml.dump({
                "auth": {"api_keys": ["sk-test"]},
                "webhook": {"bind": "0.0.0.0:8000", "work_dir": "/data/foo"},
                "repo": {"url": "git@github.com:org/dns-zones.git"},
            })
        )
        cfg = load_config(str(path))
        assert cfg.auth.api_keys == ["sk-test"]
        assert cfg.repo.url == "git@github.com:org/dns-zones.git"

    def test_missing_file(self):
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/config.yaml")

    def test_invalid_yaml(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text("auth: {bad_yaml: ")
        with pytest.raises(yaml.YAMLError):
            load_config(str(path))

    def test_missing_required_field(self, tmp_path):
        path = tmp_path / "config.yaml"
        path.write_text(yaml.dump({"auth": {"api_keys": ["k"]}}))
        with pytest.raises(ValidationError):
            load_config(str(path))
