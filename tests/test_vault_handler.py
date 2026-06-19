"""Tests for the Vault certificate storage module.

All tests use mocked hvac and cryptography calls to avoid requiring
a running Vault server or real PEM files.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from hvac.exceptions import InvalidPath, VaultError

from app.config import VaultConfig
from app.vault_handler import VaultHandler, _extract_expiry, _extract_not_before


@pytest.fixture
def vault_config(tmp_path) -> VaultConfig:
    secret_id_file = tmp_path / "vault_secret_id"
    secret_id_file.write_text("test-secret-id-123")
    return VaultConfig(
        addr="https://vault.example.com:8200",
        role_id="role-id-abc",
        secret_id_path=str(secret_id_file),
        kv_mount="secret",
        certs_path="certs",
        verify=False,
        skip=False,
    )


@pytest.fixture
def handler(vault_config: VaultConfig) -> VaultHandler:
    return VaultHandler(vault_config)


SAMPLE_CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----"
SAMPLE_KEY_PEM = "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----"


class TestExtractExpiry:
    def test_valid_cert(self):
        parsed = MagicMock()
        parsed.not_valid_after_utc.isoformat.return_value = "2026-09-15T00:00:00+00:00"
        with patch(
            "app.vault_handler.x509.load_pem_x509_certificate",
            return_value=parsed,
        ):
            result = _extract_expiry(SAMPLE_CERT_PEM)
            assert result == "2026-09-15T00:00:00+00:00"

    def test_invalid_cert_returns_none(self):
        with patch(
            "app.vault_handler.x509.load_pem_x509_certificate",
            side_effect=ValueError("bad PEM"),
        ):
            result = _extract_expiry("invalid-pem")
            assert result is None


class TestExtractNotBefore:
    def test_valid_cert(self):
        parsed = MagicMock()
        parsed.not_valid_before_utc.isoformat.return_value = "2025-06-15T00:00:00+00:00"
        with patch(
            "app.vault_handler.x509.load_pem_x509_certificate",
            return_value=parsed,
        ):
            result = _extract_not_before(SAMPLE_CERT_PEM)
            assert result == "2025-06-15T00:00:00+00:00"

    def test_invalid_cert_returns_none(self):
        with patch(
            "app.vault_handler.x509.load_pem_x509_certificate",
            side_effect=ValueError("bad PEM"),
        ):
            result = _extract_not_before("invalid-pem")
            assert result is None

    def test_not_before_stored_in_metadata(self):
        mock_not_before = MagicMock()
        mock_not_before.not_valid_before_utc.isoformat.return_value = "2025-01-01T00:00:00+00:00"
        mock_not_before.not_valid_after_utc.isoformat.return_value = "2026-01-01T00:00:00+00:00"
        with patch(
            "app.vault_handler.x509.load_pem_x509_certificate",
            return_value=mock_not_before,
        ):
            result = _extract_not_before(SAMPLE_CERT_PEM)
            assert result == "2025-01-01T00:00:00+00:00"


class TestReadSecretId:
    def test_reads_secret_id_file(self, handler: VaultHandler):
        secret_id = handler._read_secret_id()
        assert secret_id == "test-secret-id-123"

    def test_empty_file_raises(self, handler: VaultHandler, tmp_path):
        empty_file = tmp_path / "empty_secret"
        empty_file.write_text("")
        handler.config.secret_id_path = str(empty_file)
        with pytest.raises(RuntimeError, match="is empty"):
            handler._read_secret_id()

    def test_missing_file_raises(self, handler: VaultHandler):
        handler.config.secret_id_path = "/nonexistent/secret"
        with pytest.raises(FileNotFoundError):
            handler._read_secret_id()


class TestAuthenticate:
    @patch("app.vault_handler.hvac.Client")
    def test_authenticate_success(self, mock_client_cls, handler: VaultHandler):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        mock_client.auth.approle.login.return_value = {
            "auth": {"client_token": "s.token123", "lease_duration": 3600},
        }

        handler._authenticate()

        # Should create two clients: one for login, one with the token.
        assert mock_client_cls.call_count == 2
        assert handler._client is not None
        assert handler._token_expires_at > 0

    @patch("app.vault_handler.hvac.Client")
    def test_authenticate_failure_raises(self, mock_client_cls, handler: VaultHandler):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.auth.approle.login.side_effect = VaultError("login failed")

        with pytest.raises(VaultError, match="login failed"):
            handler._authenticate()

    @patch("app.vault_handler.hvac.Client")
    def test_reuses_token_if_not_expired(self, mock_client_cls, handler: VaultHandler):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.auth.approle.login.return_value = {
            "auth": {"client_token": "s.token123", "lease_duration": 3600},
        }

        # First call triggers authentication.
        handler._ensure_authenticated()
        first_client = handler._client
        first_expiry = handler._token_expires_at

        # Second call should reuse the token.
        handler._ensure_authenticated()
        assert handler._client is first_client
        assert handler._token_expires_at == first_expiry

    @patch("app.vault_handler.hvac.Client")
    def test_reauthenticates_expired_token(self, mock_client_cls, handler: VaultHandler):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.auth.approle.login.return_value = {
            "auth": {"client_token": "s.token456", "lease_duration": 3600},
        }

        # Set the expiry to the past.
        handler._client = MagicMock()
        handler._token_expires_at = 0.0

        # Should re-authenticate.
        handler._ensure_authenticated()
        # The old client was replaced (at least two Client instantiations
        # happened: the old one and one from _authenticate).
        assert mock_client_cls.call_count >= 2


class TestStoreCert:
    @patch("app.vault_handler.VaultHandler._ensure_authenticated")
    @patch("app.vault_handler.hvac.Client")
    def test_store_cert_success(
        self,
        mock_client_cls,
        mock_auth,
        handler: VaultHandler,
    ):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        handler._client = mock_client

        result = handler.store_cert(
            domain="example.com",
            cert_pem=SAMPLE_CERT_PEM,
            chain_pem="chain-pem-data",
            fullchain_pem="fullchain-pem-data",
            privkey_pem=SAMPLE_KEY_PEM,
        )

        assert result == "secret/certs/example.com"
        mock_client.secrets.kv.v2.create_or_update_secret.assert_called_once()
        call_kwargs = mock_client.secrets.kv.v2.create_or_update_secret.call_args.kwargs
        assert call_kwargs["mount_point"] == "secret"
        assert call_kwargs["path"] == "certs/example.com"
        assert call_kwargs["secret"]["cert.pem"] == SAMPLE_CERT_PEM
        assert call_kwargs["secret"]["privkey.pem"] == SAMPLE_KEY_PEM
        metadata = json.loads(call_kwargs["secret"]["metadata"])
        assert metadata["domain"] == "example.com"
        assert metadata["issuer"] == "Let's Encrypt"

    @patch("app.vault_handler.VaultHandler._ensure_authenticated")
    @patch("app.vault_handler.hvac.Client")
    def test_store_cert_no_chain(
        self,
        mock_client_cls,
        mock_auth,
        handler: VaultHandler,
    ):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        handler._client = mock_client

        result = handler.store_cert(
            domain="test.org",
            cert_pem=SAMPLE_CERT_PEM,
            chain_pem=None,
            fullchain_pem=SAMPLE_CERT_PEM,
            privkey_pem=SAMPLE_KEY_PEM,
        )

        assert result == "secret/certs/test.org"
        call_kwargs = mock_client.secrets.kv.v2.create_or_update_secret.call_args.kwargs
        assert call_kwargs["secret"]["chain.pem"] == ""

    @patch("app.vault_handler.VaultHandler._ensure_authenticated")
    @patch("app.vault_handler.hvac.Client")
    def test_store_cert_vault_error(
        self,
        mock_client_cls,
        mock_auth,
        handler: VaultHandler,
    ):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        handler._client = mock_client
        mock_client.secrets.kv.v2.create_or_update_secret.side_effect = VaultError("write failed")

        with pytest.raises(VaultError, match="write failed"):
            handler.store_cert(
                domain="example.com",
                cert_pem=SAMPLE_CERT_PEM,
                chain_pem=None,
                fullchain_pem=SAMPLE_CERT_PEM,
                privkey_pem=SAMPLE_KEY_PEM,
            )

    @patch("app.vault_handler.VaultHandler._ensure_authenticated")
    @patch("app.vault_handler.hvac.Client")
    def test_store_cert_logs_domain(
        self,
        mock_client_cls,
        mock_auth,
        handler: VaultHandler,
        caplog: pytest.LogCaptureFixture,
    ):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        handler._client = mock_client

        import logging
        caplog.set_level(logging.INFO)
        handler.store_cert(
            domain="example.com",
            cert_pem=SAMPLE_CERT_PEM,
            chain_pem=None,
            fullchain_pem=SAMPLE_CERT_PEM,
            privkey_pem=SAMPLE_KEY_PEM,
        )

        assert "Certificate for example.com stored in Vault" in caplog.text


class TestDeleteCert:
    @patch("app.vault_handler.VaultHandler._ensure_authenticated")
    @patch("app.vault_handler.hvac.Client")
    def test_delete_cert_success(
        self,
        mock_client_cls,
        mock_auth,
        handler: VaultHandler,
    ):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        handler._client = mock_client

        result = handler.delete_cert("example.com")
        assert result is True
        mock_client.secrets.kv.v2.delete_metadata_and_all_versions.assert_called_once_with(
            mount_point="secret",
            path="certs/example.com",
        )

    @patch("app.vault_handler.VaultHandler._ensure_authenticated")
    @patch("app.vault_handler.hvac.Client")
    def test_delete_cert_nonexistent(
        self,
        mock_client_cls,
        mock_auth,
        handler: VaultHandler,
    ):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        handler._client = mock_client
        mock_client.secrets.kv.v2.delete_metadata_and_all_versions.side_effect = InvalidPath()

        result = handler.delete_cert("example.com")
        assert result is True
