import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.cert_monitor import CertMonitor
from app.config import MonitorConfig, OpensslConfig
from app.vault_handler import _extract_not_before


def _expiry_iso(days_ahead: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days_ahead, hours=1)).isoformat()


class TestCertMonitorInit:
    def test_init_with_config(self):
        config = MonitorConfig()
        monitor = CertMonitor(config, MagicMock())
        assert monitor.config == config
        assert monitor._vault is not None
        assert monitor._scheduler is None
        assert monitor._sent_warnings == {}
        assert monitor._latest_status == []

    def test_init_without_config(self):
        monitor = CertMonitor(None, None)
        assert monitor.config is None
        assert monitor._vault is None


class TestCertMonitorLoadCerts:
    def test_no_vault_handler_returns_empty(self):
        monitor = CertMonitor(MagicMock(), None)
        assert monitor._load_certs_from_vault() == []

    def test_list_secrets_error_returns_empty(self):
        vault = MagicMock()
        vault._ensure_authenticated.side_effect = Exception("Vault error")
        monitor = CertMonitor(MagicMock(), vault)
        assert monitor._load_certs_from_vault() == []

    def test_empty_vault_returns_empty(self):
        vault = MagicMock()
        vault._client.secrets.kv.v2.list_secrets.return_value = {"data": {"keys": []}}
        monitor = CertMonitor(MagicMock(), vault)
        assert monitor._load_certs_from_vault() == []

    def test_loads_valid_certificates(self):
        vault = MagicMock()
        expiry1 = _expiry_iso(30)
        vault._client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": ["example.com/", "other.com/"]}
        }
        vault._client.secrets.kv.v2.read_secret_version.side_effect = [
            {
                "data": {
                    "data": {
                        "metadata": (
                            '{"domain": "example.com", "expiry": "' + expiry1 + '", "stored_at": "2025-01-01T00:00:00+00:00"}'
                        )
                    }
                }
            },
            {
                "data": {
                    "data": {
                        "metadata": (
                            '{"domain": "other.com", "expiry": "unknown", "stored_at": "2025-01-01T00:00:00+00:00"}'
                        )
                    }
                }
            },
        ]
        vault.config.kv_mount = "secret"
        vault.config.certs_path = "certs"

        monitor = CertMonitor(MagicMock(), vault)
        certs = monitor._load_certs_from_vault()
        assert len(certs) == 2
        assert certs[0]["domain"] == "example.com"
        assert certs[0]["days_left"] == 30
        assert certs[1]["domain"] == "other.com"
        assert certs[1]["days_left"] is None

    def test_read_cert_error_skips_domain(self):
        vault = MagicMock()
        vault._client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": ["example.com/", "bad.com/"]}
        }
        vault._client.secrets.kv.v2.read_secret_version.side_effect = [
            {
                "data": {
                    "data": {
                        "metadata": (
                            '{"domain": "example.com", "expiry": "' + _expiry_iso(60) + '", "stored_at": "2025-01-01T00:00:00+00:00"}'
                        )
                    }
                }
            },
            Exception("Read error"),
        ]
        vault.config.kv_mount = "secret"
        vault.config.certs_path = "certs"

        monitor = CertMonitor(MagicMock(), vault)
        certs = monitor._load_certs_from_vault()
        assert len(certs) == 1
        assert certs[0]["domain"] == "example.com"


    def test_check_day_threshold_returns_when_no_config(self):
        monitor = CertMonitor(None, None)
        monitor._check_day_threshold("example.com", 10)


class TestCertMonitorThreshold:
    def test_warning_logged_at_threshold(self, caplog):
        config = MonitorConfig(warn_days=[30, 14, 7], alert_webhook_url=None)
        vault = MagicMock()
        vault._client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": ["example.com/"]}
        }
        vault._client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {
                "data": {
                    "metadata": (
                        '{"domain": "example.com", "expiry": "' + _expiry_iso(20) + '", "stored_at": "2025-01-01T00:00:00+00:00"}'
                    )
                }
            }
        }
        vault.config.kv_mount = "secret"
        vault.config.certs_path = "certs"

        monitor = CertMonitor(config, vault)
        with caplog.at_level("WARNING"):
            monitor.run_check()

        assert "expires in 20 days (threshold: 30)" in caplog.text
        assert "expires in 20 days (threshold: 14)" not in caplog.text
        assert "expires in 20 days (threshold: 7)" not in caplog.text

    def test_no_duplicate_warnings(self, caplog):
        config = MonitorConfig(warn_days=[30], alert_webhook_url=None)
        vault = MagicMock()
        vault._client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": ["example.com/"]}
        }
        vault._client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {
                "data": {
                    "metadata": (
                        '{"domain": "example.com", "expiry": "' + _expiry_iso(20) + '", "stored_at": "2025-01-01T00:00:00+00:00"}'
                    )
                }
            }
        }
        vault.config.kv_mount = "secret"
        vault.config.certs_path = "certs"

        monitor = CertMonitor(config, vault)
        with caplog.at_level("WARNING"):
            monitor.run_check()
            monitor.run_check()

        warning_count = caplog.text.count("example.com expires in")
        assert warning_count == 1

    def test_webhook_alert_sent(self):
        config = MonitorConfig(
            warn_days=[30],
            alert_webhook_url="https://hooks.example.com/alert",
        )
        vault = MagicMock()
        expiry = _expiry_iso(20)
        vault._client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": ["example.com/"]}
        }
        vault._client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {
                "data": {
                    "metadata": (
                        '{"domain": "example.com", "expiry": "' + expiry + '", "stored_at": "2025-01-01T00:00:00+00:00"}'
                    )
                }
            }
        }
        vault.config.kv_mount = "secret"
        vault.config.certs_path = "certs"

        monitor = CertMonitor(config, vault)
        with patch("app.cert_monitor.httpx.post") as mock_post:
            monitor.run_check()
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert call_args[0][0] == "https://hooks.example.com/alert"
            payload = call_args[1]["json"]
            assert payload["domain"] == "example.com"
            assert payload["days_left"] == 20

    def test_webhook_alert_failure_logged(self, caplog):
        config = MonitorConfig(
            warn_days=[30],
            alert_webhook_url="https://hooks.example.com/alert",
        )
        vault = MagicMock()
        vault._client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": ["example.com/"]}
        }
        vault._client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {
                "data": {
                    "metadata": (
                        '{"domain": "example.com", "expiry": "' + _expiry_iso(20) + '", "stored_at": "2025-01-01T00:00:00+00:00"}'
                    )
                }
            }
        }
        vault.config.kv_mount = "secret"
        vault.config.certs_path = "certs"

        monitor = CertMonitor(config, vault)
        with patch("app.cert_monitor.httpx.post", side_effect=Exception("Network error")):
            with caplog.at_level("WARNING"):
                monitor.run_check()
            assert "failed to send webhook alert" in caplog.text


class TestCertMonitorRunCheck:
    def test_run_check_updates_latest_status(self):
        vault = MagicMock()
        vault._client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": ["example.com/"]}
        }
        vault._client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {
                "data": {
                    "metadata": (
                        '{"domain": "example.com", "expiry": "' + _expiry_iso(60) + '", "stored_at": "2025-01-01T00:00:00+00:00"}'
                    )
                }
            }
        }
        vault.config.kv_mount = "secret"
        vault.config.certs_path = "certs"

        monitor = CertMonitor(MonitorConfig(warn_days=[60], alert_webhook_url=None), vault)
        result = monitor.run_check()
        assert len(result) == 1
        assert monitor.get_status() == result

    def test_run_check_no_vault(self):
        monitor = CertMonitor(MonitorConfig(), None)
        result = monitor.run_check()
        assert result == []

    def test_get_status_returns_latest(self):
        vault = MagicMock()
        vault._client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": []}
        }
        vault.config.kv_mount = "secret"
        vault.config.certs_path = "certs"

        monitor = CertMonitor(MonitorConfig(warn_days=[60], alert_webhook_url=None), vault)
        monitor.run_check()
        assert monitor.get_status() == []


class TestCertMonitorStartStop:
    def test_start_noop_when_no_config(self):
        monitor = CertMonitor(None, None)
        monitor.start()
        assert monitor._scheduler is None

    def test_start_creates_scheduler_and_runs_check(self):
        vault = MagicMock()
        vault._client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": []}
        }
        vault.config.kv_mount = "secret"
        vault.config.certs_path = "certs"

        monitor = CertMonitor(MonitorConfig(check_interval_hours=24), vault)
        with patch.object(monitor, "run_check") as mock_run:
            monitor.start()
            assert monitor._scheduler is not None
            mock_run.assert_called_once()

    def test_stop_shuts_down_scheduler(self):
        vault = MagicMock()
        vault._client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": []}
        }
        vault.config.kv_mount = "secret"
        vault.config.certs_path = "certs"

        monitor = CertMonitor(MonitorConfig(check_interval_hours=24), vault)
        monitor.start()
        assert monitor._scheduler is not None
        monitor.stop()
        assert monitor._scheduler is None

    def test_stop_noop_when_no_scheduler(self):
        monitor = CertMonitor(None, None)
        monitor.stop()

    def test_start_logs_message(self, caplog):
        vault = MagicMock()
        vault._client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": []}
        }
        vault.config.kv_mount = "secret"
        vault.config.certs_path = "certs"

        monitor = CertMonitor(MonitorConfig(check_interval_hours=12), vault)
        with patch.object(monitor, "run_check"):
            with caplog.at_level("INFO"):
                monitor.start()
            assert "CertMonitor: started (interval=12h)" in caplog.text


class TestCertMonitorRenew:
    def test_run_renew_noop_when_no_command(self, caplog):
        config = MonitorConfig(renew_command=None)
        monitor = CertMonitor(config, None)
        with caplog.at_level("INFO"):
            monitor._run_renew("example.com")
        assert "renewing" not in caplog.text

    def test_run_renew_success(self, caplog):
        config = MonitorConfig(renew_command="echo renewing {domain}")
        monitor = CertMonitor(config, None)
        with caplog.at_level("INFO"):
            monitor._run_renew("example.com")
        assert "renewal succeeded for example.com" in caplog.text
        assert "CertMonitor: renewing example.com" in caplog.text
        assert "{domain}" not in caplog.text  # Vérifie que {domain} a été remplacé

    def test_run_renew_timeout(self, caplog):
        config = MonitorConfig(renew_command="sleep 10", renew_timeout=1)
        monitor = CertMonitor(config, None)
        with caplog.at_level("ERROR"):
            monitor._run_renew("example.com")
        assert "renewal timed out for example.com" in caplog.text

    def test_run_renew_failure(self, caplog):
        config = MonitorConfig(renew_command="false")
        monitor = CertMonitor(config, None)
        with caplog.at_level("ERROR"):
            monitor._run_renew("example.com")
        assert "renewal failed for example.com" in caplog.text

    def test_run_renew_no_duplicate(self):
        config = MonitorConfig(
            renew_command="echo renewing {domain}",
            renew_threshold=30,
            warn_days=[60],
        )
        vault = MagicMock()
        vault._client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": ["example.com/"]}
        }
        vault._client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {
                "data": {
                    "metadata": (
                        '{"domain": "example.com", "expiry": "'
                        + _expiry_iso(20)
                        + '", "stored_at": "2025-01-01T00:00:00+00:00"}'
                    )
                }
            }
        }
        vault.config.kv_mount = "secret"
        vault.config.certs_path = "certs"

        monitor = CertMonitor(config, vault)
        with patch.object(monitor, "_run_renew") as mock_renew:
            monitor.run_check()
            monitor.run_check()
            mock_renew.assert_called_once_with("example.com")

    def test_renew_threshold_not_reached(self):
        config = MonitorConfig(
            renew_command="echo renew",
            renew_threshold=7,
            warn_days=[60],
        )
        vault = MagicMock()
        vault._client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": ["example.com/"]}
        }
        vault._client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {
                "data": {
                    "metadata": (
                        '{"domain": "example.com", "expiry": "'
                        + _expiry_iso(20)
                        + '", "stored_at": "2025-01-01T00:00:00+00:00"}'
                    )
                }
            }
        }
        vault.config.kv_mount = "secret"
        vault.config.certs_path = "certs"

        monitor = CertMonitor(config, vault)
        with patch.object(monitor, "_run_renew") as mock_renew:
            monitor.run_check()
            mock_renew.assert_not_called()


class TestCertMonitorOpensslTemplateVars:
    def test_substitutes_key_type(self):
        config = MonitorConfig(renew_command="certbot --key-type {key_type}")
        openssl = OpensslConfig(key_algorithm="rsa")
        monitor = CertMonitor(config, None, openssl=openssl)
        with patch("app.cert_monitor.subprocess.run") as mock_run:
            monitor._run_renew("example.com")
            cmd = mock_run.call_args[0][0]
            assert "--key-type rsa" in " ".join(cmd)

    def test_substitutes_key_size(self):
        config = MonitorConfig(renew_command="certbot --rsa-key-size {key_size}")
        openssl = OpensslConfig(rsa_key_size=4096)
        monitor = CertMonitor(config, None, openssl=openssl)
        with patch("app.cert_monitor.subprocess.run") as mock_run:
            monitor._run_renew("example.com")
            cmd = mock_run.call_args[0][0]
            assert "--rsa-key-size 4096" in " ".join(cmd)

    def test_substitutes_curve(self):
        config = MonitorConfig(renew_command="certbot --elliptic-curve {curve}")
        openssl = OpensslConfig(ecdsa_curve="secp521r1")
        monitor = CertMonitor(config, None, openssl=openssl)
        with patch("app.cert_monitor.subprocess.run") as mock_run:
            monitor._run_renew("example.com")
            cmd = mock_run.call_args[0][0]
            assert "--elliptic-curve secp521r1" in " ".join(cmd)

    def test_substitutes_sig_hash(self):
        config = MonitorConfig(renew_command="openssl req -{sig_hash}")
        openssl = OpensslConfig(signature_hash="sha512")
        monitor = CertMonitor(config, None, openssl=openssl)
        with patch("app.cert_monitor.subprocess.run") as mock_run:
            monitor._run_renew("example.com")
            cmd = mock_run.call_args[0][0]
            assert "-sha512" in " ".join(cmd)

    def test_no_substitution_when_no_openssl_config(self):
        config = MonitorConfig(renew_command="certbot --key-type rsa")
        monitor = CertMonitor(config, None, openssl=None)
        with patch("app.cert_monitor.subprocess.run") as mock_run:
            monitor._run_renew("example.com")
            cmd = mock_run.call_args[0][0]
            assert "--key-type rsa" in " ".join(cmd)

    def test_all_variables_substituted(self):
        config = MonitorConfig(
            renew_command="certbot --key-type {key_type} --rsa-key-size {key_size} --elliptic-curve {curve} -{sig_hash}"
        )
        openssl = OpensslConfig(
            key_algorithm="ecdsa",
            rsa_key_size=2048,
            ecdsa_curve="secp256r1",
            signature_hash="sha256",
        )
        monitor = CertMonitor(config, None, openssl=openssl)
        with patch("app.cert_monitor.subprocess.run") as mock_run:
            monitor._run_renew("example.com")
            cmd = " ".join(mock_run.call_args[0][0])
            assert "--key-type ecdsa" in cmd
            assert "--rsa-key-size 2048" in cmd
            assert "--elliptic-curve secp256r1" in cmd
            assert "-sha256" in cmd


class TestCertMonitorRenewPercentage:
    def _make_metadata(self, days_ago: int, total_days: int) -> dict:
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        not_before = (now - timedelta(days=total_days - days_ago)).isoformat()
        expiry = (now + timedelta(days=days_ago)).isoformat()
        return {"not_before": not_before, "expiry": expiry}

    def test_renews_when_below_percentage(self):
        config = MonitorConfig(
            renew_command="echo renew",
            renew_threshold=0,
            renew_percentage=15,
            warn_days=[],
        )
        vault = MagicMock()
        vault._client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": ["example.com/"]}
        }
        metadata = self._make_metadata(days_ago=10, total_days=100)
        vault._client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"metadata": json.dumps(metadata)}}
        }
        vault.config.kv_mount = "secret"
        vault.config.certs_path = "certs"

        monitor = CertMonitor(config, vault)
        with patch.object(monitor, "_run_renew") as mock_renew:
            monitor.run_check()
            mock_renew.assert_called_once_with("example.com")

    def test_does_not_renew_when_above_percentage(self):
        config = MonitorConfig(
            renew_command="echo renew",
            renew_threshold=0,
            renew_percentage=10,
            warn_days=[],
        )
        vault = MagicMock()
        vault._client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": ["example.com/"]}
        }
        metadata = self._make_metadata(days_ago=20, total_days=100)
        vault._client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"metadata": json.dumps(metadata)}}
        }
        vault.config.kv_mount = "secret"
        vault.config.certs_path = "certs"

        monitor = CertMonitor(config, vault)
        with patch.object(monitor, "_run_renew") as mock_renew:
            monitor.run_check()
            mock_renew.assert_not_called()

    def test_falls_back_to_day_threshold_when_no_metadata(self):
        config = MonitorConfig(
            renew_command="echo renew",
            renew_threshold=30,
            renew_percentage=15,
            warn_days=[],
        )
        vault = MagicMock()
        vault._client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": ["example.com/"]}
        }
        vault._client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {
                "data": {
                    "metadata": '{"domain": "example.com", "expiry": "' + _expiry_iso(20) + '", "stored_at": "2025-01-01T00:00:00+00:00"}'
                }
            }
        }
        vault.config.kv_mount = "secret"
        vault.config.certs_path = "certs"

        monitor = CertMonitor(config, vault)
        with patch.object(monitor, "_run_renew") as mock_renew:
            monitor.run_check()
            mock_renew.assert_called_once_with("example.com")

    def test_percentage_noop_when_renew_percentage_none(self):
        config = MonitorConfig(
            renew_command="echo renew",
            renew_threshold=0,
            renew_percentage=None,
            warn_days=[],
        )
        vault = MagicMock()
        vault._client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": ["example.com/"]}
        }
        vault._client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {
                "data": {
                    "metadata": '{"domain": "example.com", "expiry": "' + _expiry_iso(20) + '", "stored_at": "2025-01-01T00:00:00+00:00"}'
                }
            }
        }
        vault.config.kv_mount = "secret"
        vault.config.certs_path = "certs"

        monitor = CertMonitor(config, vault)
        with patch.object(monitor, "_run_renew") as mock_renew:
            monitor.run_check()
            mock_renew.assert_not_called()

    def test_percentage_ignored_when_days_threshold_explicitly_hit_first(self):
        config = MonitorConfig(
            renew_command="echo renew",
            renew_threshold=30,
            renew_percentage=1,
            warn_days=[],
        )
        vault = MagicMock()
        vault._client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": ["example.com/"]}
        }
        metadata = self._make_metadata(days_ago=10, total_days=100)
        vault._client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"metadata": json.dumps(metadata)}}
        }
        vault.config.kv_mount = "secret"
        vault.config.certs_path = "certs"

        monitor = CertMonitor(config, vault)
        with patch.object(monitor, "_run_renew") as mock_renew:
            monitor.run_check()
            mock_renew.assert_called_once_with("example.com")

    def test_not_before_with_unknown_falls_back(self):
        config = MonitorConfig(
            renew_command="echo renew",
            renew_threshold=30,
            renew_percentage=15,
            warn_days=[],
        )
        vault = MagicMock()
        vault._client.secrets.kv.v2.list_secrets.return_value = {
            "data": {"keys": ["example.com/"]}
        }
        vault._client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {
                "data": {
                    "metadata": '{"domain": "example.com", "not_before": "unknown", "expiry": "' + _expiry_iso(20) + '", "stored_at": "2025-01-01T00:00:00+00:00"}'
                }
            }
        }
        vault.config.kv_mount = "secret"
        vault.config.certs_path = "certs"

        monitor = CertMonitor(config, vault)
        with patch.object(monitor, "_run_renew") as mock_renew:
            monitor.run_check()
            mock_renew.assert_called_once_with("example.com")


class TestExtractNotBeforeDirect:
    def test_valid_cert(self):
        parsed = MagicMock()
        parsed.not_valid_before_utc.isoformat.return_value = "2025-01-01T00:00:00+00:00"
        with patch(
            "app.vault_handler.x509.load_pem_x509_certificate",
            return_value=parsed,
        ):
            result = _extract_not_before("-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----")
            assert result == "2025-01-01T00:00:00+00:00"

    def test_invalid_cert_returns_none(self):
        with patch(
            "app.vault_handler.x509.load_pem_x509_certificate",
            side_effect=ValueError("bad PEM"),
        ):
            result = _extract_not_before("invalid-pem")
            assert result is None
