from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from app.targets.ivanti import IvantiTarget, _read_api_key
from app.config import IvantiTargetConfig


class TestReadApiKey:
    def test_reads_api_key_file(self, tmp_path: Path):
        key_file = tmp_path / "ivanti_key"
        key_file.write_text("sk-ivanti-secret\n")
        assert _read_api_key(str(key_file)) == "sk-ivanti-secret"

    def test_missing_file_raises(self):
        with pytest.raises(RuntimeError, match="not found"):
            _read_api_key("/nonexistent/path")

    def test_empty_file_raises(self, tmp_path: Path):
        key_file = tmp_path / "empty_key"
        key_file.write_text("")
        with pytest.raises(RuntimeError, match="empty"):
            _read_api_key(str(key_file))


class TestIvantiTarget:
    @pytest.fixture
    def target_config(self, tmp_path: Path):
        key_file = tmp_path / "ivanti_key"
        key_file.write_text("sk-ivanti-secret")
        return IvantiTargetConfig(
            name="ivanti-vpn",
            addr="https://ivanti.example.com",
            api_key_path=str(key_file),
            verify=False,
        )

    @pytest.fixture
    def target(self, target_config):
        return IvantiTarget(target_config)

    def test_init_sets_config(self, target, target_config):
        assert target.name == "ivanti-vpn"
        assert target.provider_type == "ivanti"
        assert target.timeout == 60

    def test_ensure_client_creates_httpx_client(self, target):
        client = target._ensure_client()
        assert isinstance(client, httpx.Client)
        assert str(client.base_url) == "https://ivanti.example.com"
        assert client.headers["Authorization"] == "Bearer sk-ivanti-secret"
        assert target._client is client

    def test_ensure_client_reuses_existing(self, target):
        c1 = target._ensure_client()
        c2 = target._ensure_client()
        assert c1 is c2

    def test_deploy_success(self, target):
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_client.post.return_value = mock_response
        target._client = mock_client

        with patch("app.targets.ivanti.pem_to_pfx") as mock_pfx:
            mock_pfx.return_value = (b"pfx-bytes", "random-pwd")

            result = target.deploy("example.com", "fullchain", "key")

        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        assert call_args[0][0] == "/api/v1/system/certificates/device-certificates"
        payload = call_args[1]["json"]
        assert payload["password"] == "random-pwd"
        assert payload["cert"] is not None
        assert payload["internalPorts"] == []
        assert payload["externalPorts"] == []
        assert payload["managementInterface"] is False

        assert result.status == "ok"
        assert result.target == "ivanti-vpn"
        assert result.provider == "ivanti"

    def test_deploy_api_error(self, target):
        mock_client = MagicMock()
        mock_client.post.side_effect = httpx.HTTPStatusError(
            "401 Unauthorized", request=MagicMock(), response=MagicMock()
        )
        target._client = mock_client

        with patch("app.targets.ivanti.pem_to_pfx") as mock_pfx:
            mock_pfx.return_value = (b"pfx-bytes", "random-pwd")
            result = target.deploy("example.com", "fullchain", "key")

        assert result.status == "error"
        assert "401" in (result.error or "")

    def test_close(self, target):
        mock_client = MagicMock()
        target._client = mock_client
        target.close()
        mock_client.close.assert_called_once()
        assert target._client is None

    def test_close_no_client(self, target):
        target.close()
        assert target._client is None


class TestIvantiTargetConfig:
    def test_default_provider(self):
        cfg = IvantiTargetConfig(
            name="test", addr="https://example.com", api_key_path="/path/to/key"
        )
        assert cfg.provider == "ivanti"
        assert cfg.timeout == 60
        assert cfg.internal_ports == []
        assert cfg.external_ports == []
        assert cfg.management_interface is False
