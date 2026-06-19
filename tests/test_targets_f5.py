from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from app.targets.f5 import F5Target, read_password, sanitize_name
from app.config import F5TargetConfig


class TestSanitizeName:
    def test_normal_domain(self):
        assert sanitize_name("example.com") == "example.com"

    def test_wildcard_domain(self):
        assert sanitize_name("*.example.com") == "wildcard.example.com"


class TestReadPassword:
    def test_reads_password_file(self, tmp_path: Path):
        pw_file = tmp_path / "f5_pass"
        pw_file.write_text("my-secret-password\n")
        assert read_password(str(pw_file)) == "my-secret-password"

    def test_missing_file_raises(self):
        with pytest.raises(RuntimeError, match="not found"):
            read_password("/nonexistent/path")

    def test_empty_file_raises(self, tmp_path: Path):
        pw_file = tmp_path / "empty_pass"
        pw_file.write_text("")
        with pytest.raises(RuntimeError, match="empty"):
            read_password(str(pw_file))

    def test_whitespace_only_file_raises(self, tmp_path: Path):
        pw_file = tmp_path / "ws_pass"
        pw_file.write_text("   \n")
        with pytest.raises(RuntimeError, match="empty"):
            read_password(str(pw_file))


class TestF5ApiCallsDirect:
    """Cover _api_post, _api_put, _api_get directly."""

    @pytest.fixture
    def target(self, tmp_path: Path):
        pw_file = tmp_path / "f5_pass"
        pw_file.write_text("secret")
        cfg = F5TargetConfig(
            name="f5-paris",
            addr="https://bigip.example.com",
            username="admin",
            password_path=str(pw_file),
            verify=False,
        )
        return F5Target(cfg)

    def test_api_post_calls_client_post(self, target):
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"result": "ok"}
        mock_client.post.return_value = mock_resp
        target._client = mock_client

        result = target._api_post("sys/file/ssl-cert", {"name": "test"})

        mock_client.post.assert_called_once_with(
            "/mgmt/tm/sys/file/ssl-cert", json={"name": "test"}
        )
        assert result == {"result": "ok"}

    def test_api_put_calls_client_put(self, target):
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"result": "ok"}
        mock_client.put.return_value = mock_resp
        target._client = mock_client

        result = target._api_put("ltm/profile/client-ssl/Common/test", {"cert": "/Common/x"})

        mock_client.put.assert_called_once_with(
            "/mgmt/tm/ltm/profile/client-ssl/Common/test", json={"cert": "/Common/x"}
        )
        assert result == {"result": "ok"}

    def test_api_get_calls_client_get(self, target):
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"items": []}
        mock_client.get.return_value = mock_resp
        target._client = mock_client

        result = target._api_get("ltm/profile/client-ssl?$select=name")

        mock_client.get.assert_called_once_with(
            "/mgmt/tm/ltm/profile/client-ssl?$select=name"
        )
        assert result == {"items": []}

    def test_api_post_raises_on_http_error(self, target):
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "404", request=MagicMock(), response=MagicMock()
        )
        mock_client.post.return_value = mock_resp
        target._client = mock_client

        with pytest.raises(httpx.HTTPStatusError):
            target._api_post("sys/file/ssl-cert", {})


class TestF5Target:
    @pytest.fixture
    def target_config(self, tmp_path: Path):
        pw_file = tmp_path / "f5_pass"
        pw_file.write_text("secret")
        return F5TargetConfig(
            name="f5-paris",
            addr="https://bigip.example.com",
            username="admin",
            password_path=str(pw_file),
            verify=False,
        )

    @pytest.fixture
    def target(self, target_config):
        return F5Target(target_config)

    def test_init_sets_config(self, target, target_config):
        assert target.name == "f5-paris"
        assert target.provider_type == "f5"
        assert target.timeout == 30

    def test_ensure_client_creates_httpx_client(self, target):
        client = target._ensure_client()
        assert isinstance(client, httpx.Client)
        assert str(client.base_url) == "https://bigip.example.com"
        assert target._client is client

    def test_ensure_client_reuses_existing(self, target):
        c1 = target._ensure_client()
        c2 = target._ensure_client()
        assert c1 is c2

    def test_upload_cert(self, target):
        with patch.object(target, "_api_post") as mock_post:
            result = target._upload_cert("example.com", "cert-pem-data")
        mock_post.assert_called_once_with(
            "sys/file/ssl-cert",
            {"name": "/Common/example.com", "content": "cert-pem-data"},
        )
        assert result == "/Common/example.com"

    def test_upload_key(self, target):
        with patch.object(target, "_api_post") as mock_post:
            result = target._upload_key("example.com", "key-pem-data")
        mock_post.assert_called_once_with(
            "sys/file/ssl-key",
            {"name": "/Common/example.com", "content": "key-pem-data"},
        )
        assert result == "/Common/example.com"

    def test_find_ssl_profiles_matching_domain(self, target):
        mock_resp = {
            "items": [
                {"name": "example.com-ssl", "cert": "/Common/example.com", "key": "/Common/example.com"},
                {"name": "other-ssl", "cert": "/Common/other.com", "key": "/Common/other.com"},
            ]
        }
        with patch.object(target, "_api_get", return_value=mock_resp):
            profiles = target._find_ssl_profiles_for_domain("example.com")
        assert profiles == ["example.com-ssl"]

    def test_find_ssl_profiles_no_match(self, target):
        mock_resp = {
            "items": [
                {"name": "other-ssl", "cert": "/Common/other.com", "key": "/Common/other.com"},
            ]
        }
        with patch.object(target, "_api_get", return_value=mock_resp):
            profiles = target._find_ssl_profiles_for_domain("example.com")
        assert profiles == []

    def test_find_ssl_profiles_error(self, target):
        with patch.object(target, "_api_get", side_effect=Exception("API error")):
            profiles = target._find_ssl_profiles_for_domain("example.com")
        assert profiles == []

    def test_find_ssl_profiles_wildcard(self, target):
        mock_resp = {
            "items": [
                {"name": "wildcard-ssl", "cert": "/Common/wildcard.example.com", "key": "/Common/wildcard.example.com"},
            ]
        }
        with patch.object(target, "_api_get", return_value=mock_resp):
            profiles = target._find_ssl_profiles_for_domain("*.example.com")
        assert profiles == ["wildcard-ssl"]

    def test_update_profile_cert(self, target):
        with patch.object(target, "_api_put") as mock_put:
            target._update_profile_cert("example-ssl", "/Common/example.com", "/Common/example.com")
        mock_put.assert_called_once_with(
            "ltm/profile/client-ssl/Common/example-ssl",
            {"cert": "/Common/example.com", "key": "/Common/example.com"},
        )

    def test_deploy_updates_profiles(self, target):
        target._upload_cert = MagicMock(return_value="/Common/example.com")
        target._upload_key = MagicMock(return_value="/Common/example.com")
        target._find_ssl_profiles_for_domain = MagicMock(return_value=["example-ssl"])
        target._update_profile_cert = MagicMock()

        result = target.deploy("example.com", "fullchain", "key")

        target._upload_cert.assert_called_once_with("example.com", "fullchain")
        target._upload_key.assert_called_once_with("example.com", "key")
        target._update_profile_cert.assert_called_once_with(
            "example-ssl", "/Common/example.com", "/Common/example.com"
        )
        assert result.status == "ok"
        assert result.target == "f5-paris"
        assert result.details["host"] == "https://bigip.example.com"
        assert result.details["updated_profiles"] == ["example-ssl"]

    def test_deploy_no_profiles(self, target):
        target._upload_cert = MagicMock(return_value="/Common/example.com")
        target._upload_key = MagicMock(return_value="/Common/example.com")
        target._find_ssl_profiles_for_domain = MagicMock(return_value=[])

        result = target.deploy("example.com", "fullchain", "key")

        assert result.status == "ok"
        assert result.details["updated_profiles"] == []

    def test_close(self, target):
        mock_client = MagicMock()
        target._client = mock_client
        target.close()
        mock_client.close.assert_called_once()
        assert target._client is None

    def test_close_no_client(self, target):
        target.close()
        assert target._client is None


class TestF5TargetConfig:
    def test_default_provider(self):
        cfg = F5TargetConfig(
            name="test",
            addr="https://example.com",
            username="admin",
            password_path="/path/to/pw",
        )
        assert cfg.provider == "f5"
        assert cfg.timeout == 30
