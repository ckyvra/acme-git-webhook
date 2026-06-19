from pathlib import Path
from unittest.mock import MagicMock, patch

import dns.exception
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.txtbase
import pytest
from fastapi.testclient import TestClient
from git import Repo

from app.config import AppConfig, AuthConfig, DnsConfig, F5Config, F5HostConfig, F5TargetConfig, MonitorConfig, RepoConfig, VaultConfig, WebhookConfig
from app.main import app
from app.targets.base import DeployResult
from app.targets.manager import DeployManager


def _make_txt_rdata(value: str):
    return dns.rdtypes.txtbase.TXTBase(
        dns.rdataclass.IN,
        dns.rdatatype.TXT,
        [value.encode()],
    )


@pytest.fixture(autouse=True)
def _setup_config(tmp_path: Path, bare_git_repo: Path):
    global_config = AppConfig(
        auth=AuthConfig(api_keys=["test-key"]),
        webhook=WebhookConfig(work_dir=str(tmp_path / "webhook")),
        repo=RepoConfig(
            url=str(bare_git_repo),
            branch="main",
            zone_path="zones",
            zone_file_suffix=".zone",
        ),
    )
    import app.main as m

    m.config = global_config
    yield
    m.config = None


@pytest.fixture
def client():
    return TestClient(app)


class TestHealth:
    def test_health_returns_ok(self, client: TestClient):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


class TestAcmeAuth:
    def test_auth_with_valid_key(self, client: TestClient, tmp_path: Path):
        payload = {
            "domain": "_acme-challenge.example.com",
            "validation": "abc123",
        }
        resp = client.post(
            "/acme/auth",
            json=payload,
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["domain"] == "_acme-challenge.example.com"

    def test_auth_fallback_nameservers_with_dns_config(self, client: TestClient, tmp_path: Path, bare_git_repo: Path):
        import app.main as m

        m.config = AppConfig(
            auth=AuthConfig(api_keys=["test-key"]),
            webhook=WebhookConfig(work_dir=str(tmp_path / "webhook")),
            repo=RepoConfig(
                url=str(bare_git_repo),
                branch="main",
                zone_path="zones",
                zone_file_suffix=".zone",
            ),
            dns=DnsConfig(
                nameservers=["127.0.0.1", "10.0.0.1"],
                timeout=10,
                poll_interval=1,
                wait_for_propagation=True,
            ),
        )

        payload = {
            "domain": "_acme-challenge.example.com",
            "validation": "abc123",
        }

        with patch("app.main.check_propagation") as mock_check:
            mock_check.return_value = {
                "matched": ["8.8.8.8", "1.1.1.1"],
                "pending": [],
                "elapsed": 1,
            }
            resp = client.post(
                "/acme/auth",
                json=payload,
                headers={"Authorization": "Bearer test-key"},
            )

        assert resp.status_code == 200
        mock_check.assert_called_once()
        args, kwargs = mock_check.call_args
        assert args[2] == ["8.8.8.8", "1.1.1.1"]

    def test_auth_with_invalid_key(self, client: TestClient):
        payload = {"domain": "_acme-challenge.example.com", "validation": "x"}
        resp = client.post(
            "/acme/auth",
            json=payload,
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert resp.status_code == 401

    def test_auth_without_auth_header(self, client: TestClient):
        payload = {"domain": "_acme-challenge.example.com", "validation": "x"}
        resp = client.post("/acme/auth", json=payload)
        assert resp.status_code == 401

    def test_auth_creates_txt_in_zone_file(self, client: TestClient, tmp_path: Path, bare_git_repo: Path):
        payload = {
            "domain": "_acme-challenge.example.com",
            "validation": "txt123",
        }
        resp = client.post(
            "/acme/auth",
            json=payload,
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 200

        clone_dir = tmp_path / "verify-clone"
        Repo.clone_from(str(bare_git_repo), str(clone_dir))
        zone_content = (clone_dir / "zones" / "example.com.zone").read_text()
        assert "txt123" in zone_content


class TestAcmeAuthEdgeCases:
    def test_auth_invalid_domain_returns_422(self, client: TestClient):
        payload = {
            "domain": "not-a-valid-acme-domain",
            "validation": "abc123",
        }
        resp = client.post(
            "/acme/auth",
            json=payload,
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 422


class TestAcmeCleanup:
    def test_cleanup_after_auth(self, client: TestClient, tmp_path: Path, bare_git_repo: Path):
        auth_payload = {
            "domain": "_acme-challenge.example.com",
            "validation": "cleanme",
        }
        client.post(
            "/acme/auth",
            json=auth_payload,
            headers={"Authorization": "Bearer test-key"},
        )

        cleanup_payload = {"domain": "_acme-challenge.example.com"}
        resp = client.post(
            "/acme/cleanup",
            json=cleanup_payload,
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    def test_cleanup_with_invalid_key(self, client: TestClient):
        payload = {"domain": "_acme-challenge.example.com"}
        resp = client.post(
            "/acme/cleanup",
            json=payload,
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert resp.status_code == 401

    def test_cleanup_idempotent(self, client: TestClient):
        payload = {"domain": "_acme-challenge.example.com"}
        resp = client.post(
            "/acme/cleanup",
            json=payload,
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "skipped"


class TestAcmeWaitForPropagation:
    def test_propagation_with_valid_key(self, client: TestClient):
        answer = MagicMock()
        answer.__iter__.return_value = [_make_txt_rdata("abc123")]
        payload = {
            "domain": "_acme-challenge.example.com",
            "validation": "abc123",
            "timeout": 10,
            "poll_interval": 1,
        }
        with patch.object(dns.resolver.Resolver, "resolve", return_value=answer):
            resp = client.post(
                "/acme/wait-for-propagation",
                json=payload,
                headers={"Authorization": "Bearer test-key"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "propagated"
        assert len(data["matched"]) == 2  # default NS: 8.8.8.8, 1.1.1.1

    def test_propagation_timeout(self, client: TestClient):
        payload = {
            "domain": "_acme-challenge.example.com",
            "validation": "abc123",
            "nameservers": ["8.8.8.8"],
            "timeout": 1,
            "poll_interval": 1,
        }
        with patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.exception.DNSException):
            resp = client.post(
                "/acme/wait-for-propagation",
                json=payload,
                headers={"Authorization": "Bearer test-key"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "timeout"
        assert data["pending"] == ["8.8.8.8"]

    def test_propagation_with_invalid_key(self, client: TestClient):
        payload = {"domain": "_acme-challenge.example.com", "validation": "x"}
        resp = client.post(
            "/acme/wait-for-propagation",
            json=payload,
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert resp.status_code == 401

    def test_propagation_without_auth_header(self, client: TestClient):
        payload = {"domain": "_acme-challenge.example.com", "validation": "x"}
        resp = client.post("/acme/wait-for-propagation", json=payload)
        assert resp.status_code == 401

    def test_propagation_custom_nameservers(self, client: TestClient):
        answer = MagicMock()
        answer.__iter__.return_value = [_make_txt_rdata("val")]
        payload = {
            "domain": "_acme-challenge.example.com",
            "validation": "val",
            "nameservers": ["4.4.4.4", "8.8.4.4"],
            "timeout": 10,
            "poll_interval": 1,
        }
        with patch.object(dns.resolver.Resolver, "resolve", return_value=answer):
            resp = client.post(
                "/acme/wait-for-propagation",
                json=payload,
                headers={"Authorization": "Bearer test-key"},
            )
        assert resp.status_code == 200
        assert resp.json()["matched"] == ["4.4.4.4", "8.8.4.4"]

    def test_propagation_filters_private_ns(self, client: TestClient):
        """All private/loopback nameservers should be replaced by defaults."""
        answer = MagicMock()
        answer.__iter__.return_value = [_make_txt_rdata("val")]
        payload = {
            "domain": "_acme-challenge.example.com",
            "validation": "val",
            "nameservers": ["127.0.0.1", "10.0.0.1"],
            "timeout": 10,
            "poll_interval": 1,
        }
        with patch.object(dns.resolver.Resolver, "resolve", return_value=answer):
            resp = client.post(
                "/acme/wait-for-propagation",
                json=payload,
                headers={"Authorization": "Bearer test-key"},
            )
        assert resp.status_code == 200
        # Should have fallen back to 8.8.8.8, 1.1.1.1
        assert resp.json()["matched"] == ["8.8.8.8", "1.1.1.1"]


class TestAcmeDeploy:
    def test_deploy_skipped_when_vault_disabled(self, client: TestClient):
        payload = {
            "domain": "example.com",
            "cert_pem": "cert-data",
            "fullchain_pem": "fullchain-data",
            "privkey_pem": "key-data",
        }
        resp = client.post(
            "/acme/deploy",
            json=payload,
            headers={"Authorization": "Bearer test-key"},
        )
        # No vault config in fixture => skipped
        assert resp.status_code == 200
        assert resp.json()["status"] == "skipped"
        assert "Vault not configured" in resp.json()["detail"]

    def test_deploy_with_invalid_key(self, client: TestClient):
        payload = {
            "domain": "example.com",
            "cert_pem": "cert",
            "fullchain_pem": "fullchain",
            "privkey_pem": "key",
        }
        resp = client.post(
            "/acme/deploy",
            json=payload,
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert resp.status_code == 401

    def test_deploy_without_auth_header(self, client: TestClient):
        payload = {
            "domain": "example.com",
            "cert_pem": "cert",
            "fullchain_pem": "fullchain",
            "privkey_pem": "key",
        }
        resp = client.post("/acme/deploy", json=payload)
        assert resp.status_code == 401

    def test_deploy_with_vault_enabled(self, client: TestClient, tmp_path: Path):
        secret_id_file = tmp_path / "vault_secret_id"
        secret_id_file.write_text("test-secret-id")

        import app.main as m

        m.config = AppConfig(
            auth=AuthConfig(api_keys=["test-key"]),
            webhook=WebhookConfig(work_dir=str(tmp_path / "webhook")),
            repo=RepoConfig(
                url=str(tmp_path / "fake.git"),
                branch="main",
                zone_path="zones",
                zone_file_suffix=".zone",
            ),
            vault=VaultConfig(
                addr="https://vault.example.com:8200",
                role_id="role-abc",
                secret_id_path=str(secret_id_file),
                verify=False,
                skip=False,
            ),
        )
        m.vault_handler = MagicMock()
        m.vault_handler.store_cert.return_value = "secret/certs/example.com"

        payload = {
            "domain": "example.com",
            "cert_pem": "cert-data",
            "chain_pem": "chain-data",
            "fullchain_pem": "fullchain-data",
            "privkey_pem": "key-data",
        }
        resp = client.post(
            "/acme/deploy",
            json=payload,
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["vault_path"] == "secret/certs/example.com"
        m.vault_handler.store_cert.assert_called_once_with(
            domain="example.com",
            cert_pem="cert-data",
            chain_pem="chain-data",
            fullchain_pem="fullchain-data",
            privkey_pem="key-data",
        )

    def test_deploy_vault_error_returns_502(self, client: TestClient, tmp_path: Path):
        secret_id_file = tmp_path / "vault_secret_id"
        secret_id_file.write_text("test-secret-id")

        import app.main as m

        m.config = AppConfig(
            auth=AuthConfig(api_keys=["test-key"]),
            webhook=WebhookConfig(work_dir=str(tmp_path / "webhook")),
            repo=RepoConfig(
                url=str(tmp_path / "fake.git"),
                branch="main",
                zone_path="zones",
                zone_file_suffix=".zone",
            ),
            vault=VaultConfig(
                addr="https://vault.example.com:8200",
                role_id="role-abc",
                secret_id_path=str(secret_id_file),
                verify=False,
                skip=False,
            ),
        )
        mock_handler = MagicMock()
        mock_handler.store_cert.side_effect = Exception("Vault connection refused")
        m.vault_handler = mock_handler

        payload = {
            "domain": "example.com",
            "cert_pem": "cert",
            "fullchain_pem": "fullchain",
            "privkey_pem": "key",
        }
        resp = client.post(
            "/acme/deploy",
            json=payload,
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 502
        assert "Vault operation failed" in resp.json()["detail"]


class TestAcmeLockTimeout:
    def test_auth_lock_timeout_returns_423(self, client: TestClient):
        payload = {
            "domain": "_acme-challenge.example.com",
            "validation": "abc123",
        }
        with patch("fasteners.InterProcessLock.acquire", return_value=False):
            resp = client.post(
                "/acme/auth",
                json=payload,
                headers={"Authorization": "Bearer test-key"},
            )
        assert resp.status_code == 423

    def test_cleanup_lock_timeout_returns_423(self, client: TestClient):
        payload = {"domain": "_acme-challenge.example.com"}
        with patch("fasteners.InterProcessLock.acquire", return_value=False):
            resp = client.post(
                "/acme/cleanup",
                json=payload,
                headers={"Authorization": "Bearer test-key"},
            )
        assert resp.status_code == 423


class TestAcmeDeployEdgeCases:
    def test_deploy_invalid_domain_returns_422(self, client: TestClient):
        payload = {
            "domain": "",
            "cert_pem": "cert",
            "fullchain_pem": "fullchain",
            "privkey_pem": "key",
        }
        resp = client.post(
            "/acme/deploy",
            json=payload,
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 422

    def test_deploy_vault_handler_none_returns_502(self, client: TestClient, tmp_path: Path):
        secret_id_file = tmp_path / "vault_secret_id"
        secret_id_file.write_text("test-secret-id")

        import app.main as m

        m.config = AppConfig(
            auth=AuthConfig(api_keys=["test-key"]),
            webhook=WebhookConfig(work_dir=str(tmp_path / "webhook")),
            repo=RepoConfig(
                url=str(tmp_path / "fake.git"),
                branch="main",
                zone_path="zones",
                zone_file_suffix=".zone",
            ),
            vault=VaultConfig(
                addr="https://vault.example.com:8200",
                role_id="role-abc",
                secret_id_path=str(secret_id_file),
                verify=False,
                skip=False,
            ),
        )
        m.vault_handler = None

        payload = {
            "domain": "example.com",
            "cert_pem": "cert",
            "fullchain_pem": "fullchain",
            "privkey_pem": "key",
        }
        resp = client.post(
            "/acme/deploy",
            json=payload,
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 502
        assert "Vault handler not initialised" in resp.json()["detail"]


class TestAcmeHealth:
    def test_health_with_rate_limit(self, client: TestClient):
        for _ in range(5):
            resp = client.get("/health")
            assert resp.status_code == 200


class TestCertsStatus:
    def test_status_not_configured(self, client: TestClient):
        resp = client.get(
            "/certs/status",
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 200
        assert resp.json() == {"certs": [], "detail": "Monitoring not configured"}

    def test_status_with_monitor(self, client: TestClient, tmp_path: Path):
        import app.main as m

        m.config = AppConfig(
            auth=AuthConfig(api_keys=["test-key"]),
            webhook=WebhookConfig(work_dir=str(tmp_path / "webhook")),
            repo=RepoConfig(
                url=str(tmp_path / "fake.git"),
                branch="main",
                zone_path="zones",
                zone_file_suffix=".zone",
            ),
            monitor=MonitorConfig(
                check_interval_hours=24,
                warn_days=[60, 30],
                alert_webhook_url=None,
            ),
        )
        mock_monitor = MagicMock()
        mock_monitor.get_status.return_value = [
            {"domain": "example.com", "days_left": 45, "expiry": "2030-01-01T00:00:00+00:00"},
        ]
        m.cert_monitor = mock_monitor

        resp = client.get(
            "/certs/status",
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 200
        assert resp.json() == {
            "certs": [{"domain": "example.com", "days_left": 45, "expiry": "2030-01-01T00:00:00+00:00"}],
        }

    def test_status_without_auth(self, client: TestClient):
        resp = client.get("/certs/status")
        assert resp.status_code == 401


class TestAcmeAuthWithDnsConfig:
    def test_auth_with_auto_propagation(self, client: TestClient, tmp_path: Path, bare_git_repo: Path):
        import app.main as m

        m.config = AppConfig(
            auth=AuthConfig(api_keys=["test-key"]),
            webhook=WebhookConfig(work_dir=str(tmp_path / "webhook")),
            repo=RepoConfig(
                url=str(bare_git_repo),
                branch="main",
                zone_path="zones",
                zone_file_suffix=".zone",
            ),
            dns=DnsConfig(
                nameservers=["8.8.8.8", "1.1.1.1"],
                timeout=10,
                poll_interval=1,
                wait_for_propagation=True,
            ),
        )

        payload = {
            "domain": "_acme-challenge.example.com",
            "validation": "abc123",
        }

        with patch("app.main.check_propagation") as mock_check:
            mock_check.return_value = {
                "matched": ["8.8.8.8", "1.1.1.1"],
                "pending": [],
                "elapsed": 2,
            }
            resp = client.post(
                "/acme/auth",
                json=payload,
                headers={"Authorization": "Bearer test-key"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["propagation"] == "propagated"
        assert data["propagation_matched"] == ["8.8.8.8", "1.1.1.1"]
        assert data["propagation_pending"] == []
        assert data["propagation_elapsed"] == 2

    def test_auth_with_auto_propagation_timeout(self, client: TestClient, tmp_path: Path, bare_git_repo: Path):
        import app.main as m

        m.config = AppConfig(
            auth=AuthConfig(api_keys=["test-key"]),
            webhook=WebhookConfig(work_dir=str(tmp_path / "webhook")),
            repo=RepoConfig(
                url=str(bare_git_repo),
                branch="main",
                zone_path="zones",
                zone_file_suffix=".zone",
            ),
            dns=DnsConfig(
                nameservers=["8.8.8.8"],
                timeout=1,
                poll_interval=1,
                wait_for_propagation=True,
            ),
        )

        payload = {
            "domain": "_acme-challenge.example.com",
            "validation": "abc123",
        }

        with patch("app.main.check_propagation") as mock_check:
            mock_check.return_value = {
                "matched": [],
                "pending": ["8.8.8.8"],
                "elapsed": 1,
            }
            resp = client.post(
                "/acme/auth",
                json=payload,
                headers={"Authorization": "Bearer test-key"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["propagation"] == "timeout"

    def test_auth_without_validation_no_propagation(self, client: TestClient, tmp_path: Path, bare_git_repo: Path):
        import app.main as m

        m.config = AppConfig(
            auth=AuthConfig(api_keys=["test-key"]),
            webhook=WebhookConfig(work_dir=str(tmp_path / "webhook")),
            repo=RepoConfig(
                url=str(bare_git_repo),
                branch="main",
                zone_path="zones",
                zone_file_suffix=".zone",
            ),
            dns=DnsConfig(wait_for_propagation=True),
        )

        payload = {"domain": "_acme-challenge.example.com", "validation": "abc123"}
        with patch("app.main.check_propagation") as mock_check:
            mock_check.return_value = {
                "matched": ["8.8.8.8", "1.1.1.1"],
                "pending": [],
                "elapsed": 1,
            }
            resp = client.post(
                "/acme/auth",
                json=payload,
                headers={"Authorization": "Bearer test-key"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["propagation"] == "propagated"


class TestAcmeDeployWithF5:
    def test_deploy_with_f5_success(self, client: TestClient, tmp_path: Path):
        import app.main as m

        m.config = AppConfig(
            auth=AuthConfig(api_keys=["test-key"]),
            webhook=WebhookConfig(work_dir=str(tmp_path / "webhook")),
            repo=RepoConfig(
                url=str(tmp_path / "fake.git"),
                branch="main",
                zone_path="zones",
                zone_file_suffix=".zone",
            ),
        )

        mock_target = MagicMock()
        mock_target.name = "f5-paris"
        mock_target.provider_type = "f5"
        mock_target.deploy.return_value = DeployResult(
            status="ok",
            target="f5-paris",
            provider="f5",
            details={"host": "https://bigip.example.com", "updated_profiles": ["example-ssl"]},
        )

        mgr = DeployManager([])
        mgr._targets = {"f5-paris": mock_target}
        m.deploy_manager = mgr

        payload = {
            "target_names": ["f5-paris"],
            "fullchain_pem": "fullchain-data",
            "privkey_pem": "key-data",
        }
        resp = client.post(
            "/deploy/example.com",
            json=payload,
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert len(data["results"]) == 1
        assert data["results"][0]["status"] == "ok"
        assert data["results"][0]["target"] == "f5-paris"
        mock_target.deploy.assert_called_once()

    def test_deploy_with_f5_error(self, client: TestClient, tmp_path: Path):
        import app.main as m

        m.config = AppConfig(
            auth=AuthConfig(api_keys=["test-key"]),
            webhook=WebhookConfig(work_dir=str(tmp_path / "webhook")),
            repo=RepoConfig(
                url=str(tmp_path / "fake.git"),
                branch="main",
                zone_path="zones",
                zone_file_suffix=".zone",
            ),
        )

        mock_target = MagicMock()
        mock_target.name = "f5-paris"
        mock_target.provider_type = "f5"
        mock_target.deploy.side_effect = Exception("F5 connection refused")

        mgr = DeployManager([])
        mgr._targets = {"f5-paris": mock_target}
        m.deploy_manager = mgr

        payload = {
            "target_names": ["f5-paris"],
            "fullchain_pem": "fullchain-data",
            "privkey_pem": "key-data",
        }
        resp = client.post(
            "/deploy/example.com",
            json=payload,
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert len(data["results"]) == 1
        assert data["results"][0]["status"] == "error"
        assert "F5 connection refused" in data["results"][0]["error"]

    def test_deploy_without_f5_config(self, client: TestClient, tmp_path: Path):
        secret_id_file = tmp_path / "vault_secret_id"
        secret_id_file.write_text("test-secret-id")

        import app.main as m

        m.config = AppConfig(
            auth=AuthConfig(api_keys=["test-key"]),
            webhook=WebhookConfig(work_dir=str(tmp_path / "webhook")),
            repo=RepoConfig(
                url=str(tmp_path / "fake.git"),
                branch="main",
                zone_path="zones",
                zone_file_suffix=".zone",
            ),
            vault=VaultConfig(
                addr="https://vault.example.com:8200",
                role_id="role-abc",
                secret_id_path=str(secret_id_file),
                verify=False,
                skip=False,
            ),
        )
        m.vault_handler = MagicMock()
        m.vault_handler.store_cert.return_value = "secret/certs/example.com"
        m.deploy_manager = None

        payload = {
            "domain": "example.com",
            "cert_pem": "cert-data",
            "fullchain_pem": "fullchain-data",
            "privkey_pem": "key-data",
        }
        resp = client.post(
            "/acme/deploy",
            json=payload,
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "results" not in data


class TestAcmeWaitForPropagationWithConfig:
    def test_uses_dns_config_defaults(self, client: TestClient, tmp_path: Path):
        import app.main as m

        m.config = AppConfig(
            auth=AuthConfig(api_keys=["test-key"]),
            webhook=WebhookConfig(work_dir=str(tmp_path / "webhook")),
            repo=RepoConfig(
                url=str(tmp_path / "fake.git"),
                branch="main",
                zone_path="zones",
                zone_file_suffix=".zone",
            ),
            dns=DnsConfig(
                nameservers=["9.9.9.9", "1.1.1.1"],
                timeout=5,
                poll_interval=1,
            ),
        )

        with patch("app.main.check_propagation") as mock_check:
            mock_check.return_value = {
                "matched": ["9.9.9.9", "1.1.1.1"],
                "pending": [],
                "elapsed": 1,
            }
            payload = {
                "domain": "_acme-challenge.example.com",
                "validation": "val",
            }
            resp = client.post(
                "/acme/wait-for-propagation",
                json=payload,
                headers={"Authorization": "Bearer test-key"},
            )

        assert resp.status_code == 200
        assert resp.json()["matched"] == ["9.9.9.9", "1.1.1.1"]
        mock_check.assert_called_once()
        _, kwargs = mock_check.call_args
        assert kwargs["timeout"] == 5
        assert kwargs["poll_interval"] == 1

    def test_request_overrides_config(self, client: TestClient, tmp_path: Path):
        import app.main as m

        m.config = AppConfig(
            auth=AuthConfig(api_keys=["test-key"]),
            webhook=WebhookConfig(work_dir=str(tmp_path / "webhook")),
            repo=RepoConfig(
                url=str(tmp_path / "fake.git"),
                branch="main",
                zone_path="zones",
                zone_file_suffix=".zone",
            ),
            dns=DnsConfig(
                nameservers=["9.9.9.9"],
                timeout=5,
                poll_interval=1,
            ),
        )

        with patch("app.main.check_propagation") as mock_check:
            mock_check.return_value = {
                "matched": ["4.4.4.4"],
                "pending": [],
                "elapsed": 1,
            }
            payload = {
                "domain": "_acme-challenge.example.com",
                "validation": "val",
                "nameservers": ["4.4.4.4"],
                "timeout": 3,
                "poll_interval": 1,
            }
            resp = client.post(
                "/acme/wait-for-propagation",
                json=payload,
                headers={"Authorization": "Bearer test-key"},
            )

        assert resp.status_code == 200
        assert resp.json()["matched"] == ["4.4.4.4"]


class TestAcmeRenew:
    def test_renew_success(self, client: TestClient, tmp_path: Path):
        import app.main as m

        m.config = AppConfig(
            auth=AuthConfig(api_keys=["test-key"]),
            webhook=WebhookConfig(work_dir=str(tmp_path / "webhook")),
            repo=RepoConfig(
                url=str(tmp_path / "fake.git"),
                branch="main",
                zone_path="zones",
                zone_file_suffix=".zone",
            ),
            monitor=MonitorConfig(renew_command="echo renew {domain}"),
        )
        mock_monitor = MagicMock()
        m.cert_monitor = mock_monitor

        resp = client.post(
            "/acme/renew",
            json={"domain": "example.com"},
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok", "domain": "example.com"}
        mock_monitor._run_renew.assert_called_once_with("example.com")

    def test_renew_not_configured(self, client: TestClient, tmp_path: Path):
        import app.main as m

        m.config = AppConfig(
            auth=AuthConfig(api_keys=["test-key"]),
            webhook=WebhookConfig(work_dir=str(tmp_path / "webhook")),
            repo=RepoConfig(
                url=str(tmp_path / "fake.git"),
                branch="main",
                zone_path="zones",
                zone_file_suffix=".zone",
            ),
        )
        m.cert_monitor = MagicMock()
        m.cert_monitor.config = MonitorConfig(renew_command=None)

        resp = client.post(
            "/acme/renew",
            json={"domain": "example.com"},
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 400
        assert "Renewal not configured" in resp.json()["detail"]

    def test_renew_monitor_none(self, client: TestClient, tmp_path: Path):
        import app.main as m

        m.config = AppConfig(
            auth=AuthConfig(api_keys=["test-key"]),
            webhook=WebhookConfig(work_dir=str(tmp_path / "webhook")),
            repo=RepoConfig(
                url=str(tmp_path / "fake.git"),
                branch="main",
                zone_path="zones",
                zone_file_suffix=".zone",
            ),
        )
        m.cert_monitor = None

        resp = client.post(
            "/acme/renew",
            json={"domain": "example.com"},
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 400
        assert "Renewal not configured" in resp.json()["detail"]

    def test_renew_with_invalid_key(self, client: TestClient):
        resp = client.post(
            "/acme/renew",
            json={"domain": "example.com"},
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert resp.status_code == 401

    def test_renew_without_auth(self, client: TestClient):
        resp = client.post(
            "/acme/renew",
            json={"domain": "example.com"},
        )
        assert resp.status_code == 401

    def test_renew_invalid_domain_returns_422(self, client: TestClient):
        resp = client.post(
            "/acme/renew",
            json={"domain": ""},
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 422


class TestListTargets:
    def test_list_targets_empty(self, client: TestClient):
        import app.main as m

        m.deploy_manager = None
        resp = client.get(
            "/targets",
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 200
        assert resp.json() == {"targets": []}

    def test_list_targets_with_targets(self, client: TestClient):
        import app.main as m

        mock_mgr = MagicMock()
        mock_mgr.targets = {"f5-0": MagicMock(provider_type="f5")}
        m.deploy_manager = mock_mgr
        resp = client.get(
            "/targets",
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 200
        assert resp.json() == {"targets": [{"name": "f5-0", "provider": "f5"}]}


class TestDeployTargets:
    def test_deploy_no_manager(self, client: TestClient):
        import app.main as m

        m.deploy_manager = None
        resp = client.post(
            "/deploy/example.com",
            json={"fullchain_pem": "chain", "privkey_pem": "key"},
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 400
        assert "No deployment targets configured" in resp.json()["detail"]

    def test_deploy_to_single_target(self, client: TestClient, tmp_path: Path):
        import app.main as m

        mock_mgr = MagicMock()
        mock_mgr.deploy.return_value = [DeployResult(target="f5-0", provider="f5", status="ok")]
        m.deploy_manager = mock_mgr
        resp = client.post(
            "/deploy/example.com/my-target",
            json={"fullchain_pem": "chain", "privkey_pem": "key"},
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 200
        mock_mgr.deploy.assert_called_once()

    def test_deploy_vault_fallback_handler_none(self, client: TestClient, tmp_path: Path):
        import app.main as m

        mock_mgr = MagicMock()
        m.deploy_manager = mock_mgr
        m.vault_handler = None
        resp = client.post(
            "/deploy/example.com",
            json={},
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 502
        assert "Vault handler not available" in resp.json()["detail"]

    def test_deploy_vault_fallback_client_none(self, client: TestClient, tmp_path: Path):
        import app.main as m

        mock_mgr = MagicMock()
        m.deploy_manager = mock_mgr
        mock_vault = MagicMock()
        mock_vault._client = None
        m.vault_handler = mock_vault
        resp = client.post(
            "/deploy/example.com",
            json={},
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 502
        assert "Vault client not initialized" in resp.json()["detail"]

    def test_deploy_vault_fallback_read_failure(self, client: TestClient, tmp_path: Path):
        import app.main as m

        mock_mgr = MagicMock()
        m.deploy_manager = mock_mgr
        mock_vault = MagicMock()
        mock_vault._client.secrets.kv.v2.read_secret_version.side_effect = RuntimeError("Vault down")
        m.vault_handler = mock_vault
        resp = client.post(
            "/deploy/example.com",
            json={},
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 502
        assert "Failed to read certificate from Vault" in resp.json()["detail"]

    def test_deploy_vault_fallback_read_success(self, client: TestClient, tmp_path: Path):
        import app.main as m

        mock_mgr = MagicMock()
        mock_mgr.deploy.return_value = [DeployResult(target="f5-0", provider="f5", status="ok")]
        m.deploy_manager = mock_mgr
        mock_vault = MagicMock()
        mock_vault._client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {
                "data": {
                    "fullchain.pem": "chain",
                    "privkey.pem": "key",
                }
            }
        }
        m.vault_handler = mock_vault
        resp = client.post(
            "/deploy/example.com",
            json={},
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 200
        mock_mgr.deploy.assert_called_once()


class TestRateLimitExceeded:
    def test_rate_limit_exceeded_handler(self):
        from unittest.mock import MagicMock as _MagicMock

        from slowapi.errors import RateLimitExceeded
        from starlette.requests import Request
        from starlette.responses import JSONResponse

        from app.main import _rate_limit_exceeded_handler

        scope = {"type": "http", "method": "GET", "path": "/health"}
        request = Request(scope)
        exc = RateLimitExceeded(limit=_MagicMock())
        response = _rate_limit_exceeded_handler(request, exc)
        assert isinstance(response, JSONResponse)
        assert response.status_code == 429
        assert response.body == b'{"detail":"Rate limit exceeded, try again later"}'


class TestLifespan:
    def test_lifespan_with_all_features(self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("CONFIG_PATH", str(tmp_path / "config.yaml"))
        secret_id_file = tmp_path / "vault_secret_id"
        secret_id_file.write_text("test-secret-id")
        pwd_file = tmp_path / "f5_password"
        pwd_file.write_text("f5-password")

        cfg = AppConfig(
            auth=AuthConfig(api_keys=["test-key"]),
            webhook=WebhookConfig(work_dir=str(tmp_path / "webhook")),
            repo=RepoConfig(url=str(tmp_path / "fake.git"), branch="main", zone_path="zones"),
            vault=VaultConfig(
                addr="https://vault.example.com:8200",
                role_id="role-abc",
                secret_id_path=str(secret_id_file),
                skip=False,
            ),
            targets=[
                F5TargetConfig(
                    name="t1",
                    addr="https://f5.example.com",
                    username="admin",
                    password_path=str(pwd_file),
                )
            ],
            f5=F5Config(
                hosts=[
                    F5HostConfig(
                        addr="https://f5.example.com",
                        username="admin",
                        password_path=str(pwd_file),
                    )
                ]
            ),
            monitor=MonitorConfig(renew_command="echo renew"),
        )

        import app.main as m

        m.cert_monitor = None
        m.deploy_manager = None
        m.config = None

        with (
            patch("app.main.load_config", return_value=cfg),
            patch("app.main.VaultHandler") as mock_vault_cls,
            patch("app.main.DeployManager") as mock_mgr_cls,
            patch("app.main.CertMonitor") as mock_mon_cls,
        ):
            with TestClient(app) as client:
                assert m.config is cfg
                mock_vault_cls.assert_called_once()
                mock_mgr_cls.assert_called_once()
                mock_mon_cls.assert_called_once()
                mock_mon_cls.return_value.start.assert_called_once()

                resp = client.get(
                    "/targets",
                    headers={"Authorization": "Bearer test-key"},
                )
                assert resp.status_code == 200

        # After lifespan shutdown, stop() and close() should have been called
        mock_mon_cls.return_value.stop.assert_called_once()
        mock_mgr_cls.return_value.close.assert_called_once()


class TestConfigNotLoaded:
    def test_config_not_loaded_returns_500(self, client: TestClient):
        import app.main as m

        m.config = None
        resp = client.post(
            "/acme/auth",
            json={"domain": "_acme-challenge.example.com", "validation": "x"},
            headers={"Authorization": "Bearer test-key"},
        )
        assert resp.status_code == 500
        assert resp.json()["detail"] == "Config not loaded"


class TestAcmeWebhookApiKey:
    def test_env_key_added_during_startup(self, monkeypatch):
        monkeypatch.setenv("ACME_WEBHOOK_API_KEY", "env-key-123")
        test_config = AppConfig(
            auth=AuthConfig(api_keys=[]),
            webhook=WebhookConfig(work_dir="/tmp"),
            repo=RepoConfig(url="fake", branch="main", zone_path="zones"),
        )
        import app.main as m

        m.cert_monitor = None
        with patch("app.main.load_config", return_value=test_config):
            with TestClient(app) as client:
                resp = client.get(
                    "/certs/status",
                    headers={"Authorization": "Bearer env-key-123"},
                )
                assert resp.status_code == 200

    def test_no_env_key_no_addition(self, monkeypatch):
        monkeypatch.delenv("ACME_WEBHOOK_API_KEY", raising=False)
        test_config = AppConfig(
            auth=AuthConfig(api_keys=["existing-key"]),
            webhook=WebhookConfig(work_dir="/tmp"),
            repo=RepoConfig(url="fake", branch="main", zone_path="zones"),
        )
        import app.main as m

        m.cert_monitor = None
        with patch("app.main.load_config", return_value=test_config):
            with TestClient(app) as client:
                resp = client.get(
                    "/certs/status",
                    headers={"Authorization": "Bearer existing-key"},
                )
                assert resp.status_code == 200

    def test_env_key_noop_when_auth_none(self, monkeypatch):
        monkeypatch.setenv("ACME_WEBHOOK_API_KEY", "env-key-123")
        test_config = AppConfig(
            auth=AuthConfig(api_keys=[]),
            webhook=WebhookConfig(work_dir="/tmp"),
            repo=RepoConfig(url="fake", branch="main", zone_path="zones"),
        )
        test_config.auth = None
        import app.main as m

        m.cert_monitor = None
        with patch("app.main.load_config", return_value=test_config):
            with TestClient(app):
                assert m.config.auth is None
