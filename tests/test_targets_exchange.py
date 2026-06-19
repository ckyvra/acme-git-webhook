from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.config import ExchangeTargetConfig
from app.targets.exchange import ExchangeTarget, _read_password


class TestReadPassword:
    def test_reads_password_file(self, tmp_path: Path):
        pw_file = tmp_path / "exchange_pass"
        pw_file.write_text("exchange-secret\n")
        assert _read_password(str(pw_file)) == "exchange-secret"

    def test_missing_file_raises(self):
        with pytest.raises(RuntimeError, match="not found"):
            _read_password("/nonexistent/path")

    def test_empty_file_raises(self, tmp_path: Path):
        pw_file = tmp_path / "empty_pass"
        pw_file.write_text("")
        with pytest.raises(RuntimeError, match="empty"):
            _read_password(str(pw_file))


class TestExchangeEnsureWinRM:
    @pytest.fixture
    def target(self, tmp_path: Path):
        pw_file = tmp_path / "exchange_pass"
        pw_file.write_text("exchange-secret")
        cfg = ExchangeTargetConfig(
            name="exchange-smtp",
            addr="https://exchange.example.com:5986",
            username="DOMAIN\\svc-cert",
            password_path=str(pw_file),
            verify=False,
        )
        return ExchangeTarget(cfg)

    def test_ensure_winrm_creates_session(self, target):
        mock_session = MagicMock()
        with patch("app.targets.exchange.winrm") as mock_winrm:
            mock_winrm.Session.return_value = mock_session
            session = target._ensure_winrm()
        assert session is mock_session
        mock_winrm.Session.assert_called_once_with(
            "https://exchange.example.com:5986",
            auth=("DOMAIN\\svc-cert", "exchange-secret"),
            transport="ntlm",
            server_cert_validation="ignore",
            operation_timeout_sec=120,
            read_timeout_sec=150,
        )

    def test_ensure_winrm_reuses_password(self, target):
        mock_session = MagicMock()
        target._password = "cached-password"
        with patch("app.targets.exchange.winrm") as mock_winrm:
            mock_winrm.Session.return_value = mock_session
            target._ensure_winrm()
        _, kwargs = mock_winrm.Session.call_args
        assert kwargs["auth"] == ("DOMAIN\\svc-cert", "cached-password")

    def test_ensure_winrm_kerberos_transport(self, tmp_path: Path):
        pw_file = tmp_path / "exchange_pass"
        pw_file.write_text("secret")
        cfg = ExchangeTargetConfig(
            name="exchange-kerb",
            addr="https://exchange.example.com:5986",
            username="user@DOMAIN.COM",
            password_path=str(pw_file),
            transport="kerberos",
            verify=True,
        )
        target = ExchangeTarget(cfg)
        with patch("app.targets.exchange.winrm") as mock_winrm:
            mock_winrm.Session.return_value = MagicMock()
            target._ensure_winrm()
        _, kwargs = mock_winrm.Session.call_args
        assert kwargs["transport"] == "kerberos"
        assert kwargs["server_cert_validation"] == "validate"


class TestExchangeTarget:
    @pytest.fixture
    def target_config(self, tmp_path: Path):
        pw_file = tmp_path / "exchange_pass"
        pw_file.write_text("exchange-secret")
        return ExchangeTargetConfig(
            name="exchange-smtp",
            addr="https://exchange.example.com:5986",
            username="DOMAIN\\svc-cert",
            password_path=str(pw_file),
            verify=False,
        )

    @pytest.fixture
    def target(self, target_config):
        return ExchangeTarget(target_config)

    def test_init_sets_config(self, target, target_config):
        assert target.name == "exchange-smtp"
        assert target.provider_type == "exchange"
        assert target.timeout == 120

    def test_deploy_success(self, target):
        mock_session = MagicMock()
        mock_upload_resp = MagicMock()
        mock_upload_resp.status_code = 0
        mock_import_resp = MagicMock()
        mock_import_resp.status_code = 0

        mock_session.run_ps.side_effect = [mock_upload_resp, mock_import_resp, mock_upload_resp]

        target._ensure_winrm = MagicMock(return_value=mock_session)

        with patch("app.targets.exchange.pem_to_pfx") as mock_pfx:
            mock_pfx.return_value = (b"pfx-bytes", "random-pwd")

            result = target.deploy("example.com", "fullchain", "key")

        assert result.status == "ok"
        assert result.target == "exchange-smtp"
        assert result.provider == "exchange"
        assert result.details["services"] == "SMTP"
        assert "example.com.pfx" in result.details["remote_path"]

        # Verify the PowerShell scripts
        calls = mock_session.run_ps.call_args_list
        assert len(calls) == 3
        # Upload script
        assert "FromBase64String" in calls[0][0][0]
        assert "example.com.pfx" in calls[0][0][0]
        # Import script
        assert "Import-ExchangeCertificate" in calls[1][0][0]
        assert "Enable-ExchangeCertificate" in calls[1][0][0]
        assert "random-pwd" in calls[1][0][0]
        assert "-Services SMTP" in calls[1][0][0]
        # Cleanup script
        assert "Remove-Item" in calls[2][0][0]

    def test_deploy_upload_failure(self, target):
        mock_session = MagicMock()
        mock_fail_resp = MagicMock()
        mock_fail_resp.status_code = 1
        mock_fail_resp.std_err = b"Access denied"
        mock_session.run_ps.return_value = mock_fail_resp

        target._ensure_winrm = MagicMock(return_value=mock_session)

        with patch("app.targets.exchange.pem_to_pfx") as mock_pfx:
            mock_pfx.return_value = (b"pfx-bytes", "random-pwd")
            result = target.deploy("example.com", "fullchain", "key")

        assert result.status == "error"
        assert "WinRM upload failed" in (result.error or "")

    def test_deploy_import_failure(self, target):
        mock_session = MagicMock()
        mock_ok_resp = MagicMock()
        mock_ok_resp.status_code = 0
        mock_fail_resp = MagicMock()
        mock_fail_resp.status_code = 1
        mock_fail_resp.std_err = b"Command not found"
        mock_session.run_ps.side_effect = [mock_ok_resp, mock_fail_resp]

        target._ensure_winrm = MagicMock(return_value=mock_session)

        with patch("app.targets.exchange.pem_to_pfx") as mock_pfx:
            mock_pfx.return_value = (b"pfx-bytes", "random-pwd")
            result = target.deploy("example.com", "fullchain", "key")

        assert result.status == "error"
        assert "import/enable failed" in (result.error or "")

    def test_close(self, target):
        target.close()

    def test_ensure_winrm_raises_without_pywinrm(self, target):
        with patch("app.targets.exchange.winrm", None):
            with pytest.raises(RuntimeError, match="pywinrm is not installed"):
                target._ensure_winrm()


class TestExchangeTargetConfig:
    def test_default_provider(self):
        cfg = ExchangeTargetConfig(
            name="test",
            addr="https://exchange.example.com:5986",
            username="DOMAIN\\user",
            password_path="/path/to/pw",
        )
        assert cfg.provider == "exchange"
        assert cfg.transport == "ntlm"
        assert cfg.services == "SMTP"
        assert cfg.timeout == 120
