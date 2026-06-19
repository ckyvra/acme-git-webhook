from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from app.config import F5Config, F5HostConfig
from app.f5_handler import F5Handler, F5HostHandler, _read_password, _sanitize_name


class TestSanitizeName:
    def test_normal_domain(self):
        assert _sanitize_name("example.com") == "example.com"

    def test_wildcard_domain(self):
        assert _sanitize_name("*.example.com") == "wildcard.example.com"


class TestReadPassword:
    def test_reads_password_file(self, tmp_path: Path):
        pw_file = tmp_path / "f5_pass"
        pw_file.write_text("my-secret-password\n")
        assert _read_password(str(pw_file)) == "my-secret-password"

    def test_missing_file_raises(self):
        with pytest.raises(RuntimeError, match="not found"):
            _read_password("/nonexistent/path")

    def test_empty_file_raises(self, tmp_path: Path):
        pw_file = tmp_path / "empty_pass"
        pw_file.write_text("")
        with pytest.raises(RuntimeError, match="empty"):
            _read_password(str(pw_file))

    def test_whitespace_only_file_raises(self, tmp_path: Path):
        pw_file = tmp_path / "ws_pass"
        pw_file.write_text("   \n")
        with pytest.raises(RuntimeError, match="empty"):
            _read_password(str(pw_file))


class TestF5HostHandler:
    @pytest.fixture
    def host_config(self, tmp_path: Path):
        pw_file = tmp_path / "f5_pass"
        pw_file.write_text("secret")
        return F5HostConfig(
            addr="https://bigip.example.com",
            username="admin",
            password_path=str(pw_file),
            verify=False,
        )

    @pytest.fixture
    def handler(self, host_config):
        return F5HostHandler(host_config)

    def test_init_sets_config(self, handler, host_config):
        assert handler.config == host_config
        assert handler._password is None
        assert handler._client is None

    def test_ensure_client_creates_httpx_client(self, handler):
        client = handler._ensure_client()
        assert isinstance(client, httpx.Client)
        assert str(client.base_url) == "https://bigip.example.com"
        assert handler._client is client

    def test_ensure_client_reuses_existing(self, handler):
        c1 = handler._ensure_client()
        c2 = handler._ensure_client()
        assert c1 is c2

    def test_upload_cert(self, handler):
        with patch.object(handler, "_api_post") as mock_post:
            result = handler._upload_cert("example.com", "cert-pem-data")
        mock_post.assert_called_once_with(
            "sys/file/ssl-cert",
            {"name": "/Common/example.com", "content": "cert-pem-data"},
        )
        assert result == "/Common/example.com"

    def test_upload_key(self, handler):
        with patch.object(handler, "_api_post") as mock_post:
            result = handler._upload_key("example.com", "key-pem-data")
        mock_post.assert_called_once_with(
            "sys/file/ssl-key",
            {"name": "/Common/example.com", "content": "key-pem-data"},
        )
        assert result == "/Common/example.com"

    def test_find_ssl_profiles_matching_domain(self, handler):
        mock_resp = {
            "items": [
                {"name": "example.com-ssl", "cert": "/Common/example.com", "key": "/Common/example.com"},
                {"name": "other-ssl", "cert": "/Common/other.com", "key": "/Common/other.com"},
            ]
        }
        with patch.object(handler, "_api_get", return_value=mock_resp):
            profiles = handler._find_ssl_profiles_for_domain("example.com")
        assert profiles == ["example.com-ssl"]

    def test_find_ssl_profiles_no_match(self, handler):
        mock_resp = {
            "items": [
                {"name": "other-ssl", "cert": "/Common/other.com", "key": "/Common/other.com"},
            ]
        }
        with patch.object(handler, "_api_get", return_value=mock_resp):
            profiles = handler._find_ssl_profiles_for_domain("example.com")
        assert profiles == []

    def test_find_ssl_profiles_error(self, handler):
        with patch.object(handler, "_api_get", side_effect=Exception("API error")):
            profiles = handler._find_ssl_profiles_for_domain("example.com")
        assert profiles == []

    def test_find_ssl_profiles_wildcard(self, handler):
        mock_resp = {
            "items": [
                {"name": "wildcard-ssl", "cert": "/Common/wildcard.example.com", "key": "/Common/wildcard.example.com"},
            ]
        }
        with patch.object(handler, "_api_get", return_value=mock_resp):
            profiles = handler._find_ssl_profiles_for_domain("*.example.com")
        assert profiles == ["wildcard-ssl"]

    def test_update_profile_cert(self, handler):
        with patch.object(handler, "_api_put") as mock_put:
            handler._update_profile_cert("example-ssl", "/Common/example.com", "/Common/example.com")
        mock_put.assert_called_once_with(
            "ltm/profile/client-ssl/Common/example-ssl",
            {"cert": "/Common/example.com", "key": "/Common/example.com"},
        )

    def test_deploy_cert_updates_profiles(self, handler):
        handler._upload_cert = MagicMock(return_value="/Common/example.com")
        handler._upload_key = MagicMock(return_value="/Common/example.com")
        handler._find_ssl_profiles_for_domain = MagicMock(return_value=["example-ssl"])
        handler._update_profile_cert = MagicMock()

        result = handler.deploy_cert("example.com", "cert", "fullchain", "key")

        handler._upload_cert.assert_called_once_with("example.com", "fullchain")
        handler._upload_key.assert_called_once_with("example.com", "key")
        handler._update_profile_cert.assert_called_once_with("example-ssl", "/Common/example.com", "/Common/example.com")
        assert result["host"] == "https://bigip.example.com"
        assert result["updated_profiles"] == ["example-ssl"]

    def test_deploy_cert_no_profiles(self, handler):
        handler._upload_cert = MagicMock(return_value="/Common/example.com")
        handler._upload_key = MagicMock(return_value="/Common/example.com")
        handler._find_ssl_profiles_for_domain = MagicMock(return_value=[])

        result = handler.deploy_cert("example.com", "cert", "fullchain", "key")

        assert result["updated_profiles"] == []

    def test_close(self, handler):
        mock_client = MagicMock()
        handler._client = mock_client
        handler.close()
        mock_client.close.assert_called_once()
        assert handler._client is None

    def test_close_no_client(self, handler):
        handler.close()
        assert handler._client is None


class TestF5Handler:
    @pytest.fixture
    def f5_config(self, tmp_path: Path):
        pw_file = tmp_path / "f5_pass"
        pw_file.write_text("secret")
        return F5Config(
            hosts=[
                F5HostConfig(
                    addr="https://bigip1.example.com",
                    username="admin",
                    password_path=str(pw_file),
                    verify=False,
                ),
                F5HostConfig(
                    addr="https://bigip2.example.com",
                    username="admin",
                    password_path=str(pw_file),
                    verify=False,
                ),
            ]
        )

    def test_deploy_cert_all_hosts_success(self, f5_config):
        handler = F5Handler(f5_config)
        for host in handler._hosts:
            host.deploy_cert = MagicMock(
                return_value={
                    "host": host.config.addr,
                    "cert_name": "/Common/example.com",
                    "key_name": "/Common/example.com",
                    "updated_profiles": ["example-ssl"],
                }
            )

        results = handler.deploy_cert("example.com", "cert", "fullchain", "key")
        assert len(results) == 2
        assert all(r["status"] == "ok" for r in results)

    def test_deploy_cert_one_host_fails(self, f5_config):
        handler = F5Handler(f5_config)
        handler._hosts[0].deploy_cert = MagicMock(side_effect=Exception("Connection failed"))
        handler._hosts[1].deploy_cert = MagicMock(
            return_value={
                "host": "https://bigip2.example.com",
                "cert_name": "/Common/example.com",
                "status": "ok",
            }
        )

        results = handler.deploy_cert("example.com", "cert", "fullchain", "key")
        assert len(results) == 2
        assert results[0]["status"] == "error"
        assert results[1]["status"] == "ok"

    def test_close(self, f5_config):
        handler = F5Handler(f5_config)
        for host in handler._hosts:
            host.close = MagicMock()
        handler.close()
        for host in handler._hosts:
            host.close.assert_called_once()


class TestF5ApiCalls:
    @pytest.fixture
    def handler(self, tmp_path: Path):
        pw_file = tmp_path / "f5_pass"
        pw_file.write_text("secret")
        config = F5HostConfig(
            addr="https://bigip.example.com",
            username="admin",
            password_path=str(pw_file),
            verify=False,
        )
        return F5HostHandler(config)

    def test_api_post_success(self, handler):
        with patch.object(handler._ensure_client(), "post") as mock_post:
            mock_response = MagicMock()
            mock_response.json.return_value = {"kind": "ssl-cert", "name": "/Common/test"}
            mock_post.return_value = mock_response

            result = handler._api_post("sys/file/ssl-cert", {"name": "test"})

            assert result == {"kind": "ssl-cert", "name": "/Common/test"}
            mock_post.assert_called_once()

    def test_api_post_raises_on_error(self, handler):
        with patch.object(handler._ensure_client(), "post") as mock_post:
            mock_response = MagicMock()
            mock_response.raise_for_status.side_effect = httpx.HTTPStatusError("error", request=MagicMock(), response=MagicMock())
            mock_post.return_value = mock_response

            with pytest.raises(httpx.HTTPStatusError):
                handler._api_post("sys/file/ssl-cert", {"name": "test"})

    def test_api_put_success(self, handler):
        with patch.object(handler._ensure_client(), "put") as mock_put:
            mock_response = MagicMock()
            mock_response.json.return_value = {"kind": "ssl-profile"}
            mock_put.return_value = mock_response

            result = handler._api_put("ltm/profile/client-ssl/test", {"cert": "/Common/test"})
            assert result == {"kind": "ssl-profile"}

    def test_api_get_success(self, handler):
        with patch.object(handler._ensure_client(), "get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = {"items": []}
            mock_get.return_value = mock_response

            result = handler._api_get("ltm/profile/client-ssl")
            assert result == {"items": []}
