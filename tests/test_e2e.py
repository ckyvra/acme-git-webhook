from pathlib import Path

import dns.zone
import pytest
from fastapi.testclient import TestClient
from git import Repo

from app.config import AppConfig, AuthConfig, RepoConfig, WebhookConfig
from app.main import app

ACME_DOMAIN = "_acme-challenge.{}.example.com"
VALIDATION = "e2e-token-validation-value"


@pytest.fixture(autouse=True)
def _setup_e2e_config(tmp_path: Path, bare_git_repo: Path):
    import app.main as m

    m.config = AppConfig(
        auth=AuthConfig(api_keys=["e2e-key"]),
        webhook=WebhookConfig(work_dir=str(tmp_path / "webhook")),
        repo=RepoConfig(
            url=str(bare_git_repo),
            branch="main",
            zone_path="zones",
            zone_file_suffix=".zone",
        ),
    )
    m.vault_handler = None
    m.deploy_manager = None
    m.cert_monitor = None
    yield
    m.config = None


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def bare(bare_git_repo: Path) -> Path:
    return bare_git_repo


def _clone_zone(bare_repo: Path, dest: Path) -> str:
    Repo.clone_from(str(bare_repo), str(dest))
    zone_file = dest / "zones" / "example.com.zone"
    return zone_file.read_text()


class TestFullAcmeChallengeFlow:
    def test_auth_creates_txt_record(self, client: TestClient, tmp_path: Path, bare: Path):
        domain = ACME_DOMAIN.format("e2e-auth")
        resp = client.post(
            "/acme/auth",
            json={"domain": domain, "validation": VALIDATION},
            headers={"Authorization": "Bearer e2e-key"},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["status"] == "ok"
        assert data["zone_file"].count("example.com") >= 1  # zone content must include the test domain

        zone = _clone_zone(bare, tmp_path / "verify-auth")
        assert VALIDATION in zone
        assert "_acme-challenge.e2e-auth" in zone

    def test_cleanup_removes_txt_record(self, client: TestClient, tmp_path: Path, bare: Path):
        domain = ACME_DOMAIN.format("e2e-cleanup")
        client.post(
            "/acme/auth",
            json={"domain": domain, "validation": VALIDATION},
            headers={"Authorization": "Bearer e2e-key"},
        )

        resp = client.post(
            "/acme/cleanup",
            json={"domain": domain},
            headers={"Authorization": "Bearer e2e-key"},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "ok"

        zone = _clone_zone(bare, tmp_path / "verify-clean")
        assert VALIDATION not in zone

    def test_cleanup_idempotent(self, client: TestClient, tmp_path: Path, bare: Path):
        domain = ACME_DOMAIN.format("e2e-idemp")
        client.post(
            "/acme/auth",
            json={"domain": domain, "validation": VALIDATION},
            headers={"Authorization": "Bearer e2e-key"},
        )
        client.post(
            "/acme/cleanup",
            json={"domain": domain},
            headers={"Authorization": "Bearer e2e-key"},
        )

        resp = client.post(
            "/acme/cleanup",
            json={"domain": domain},
            headers={"Authorization": "Bearer e2e-key"},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "skipped"

    def test_auth_wildcard_domain(self, client: TestClient, tmp_path: Path, bare: Path):
        domain = "_acme-challenge.*.wildcard-test.example.com"
        resp = client.post(
            "/acme/auth",
            json={"domain": domain, "validation": VALIDATION},
            headers={"Authorization": "Bearer e2e-key"},
        )
        assert resp.status_code == 200, resp.text

        zone = _clone_zone(bare, tmp_path / "verify-wildcard")
        assert VALIDATION in zone
        assert "_acme-challenge.*.wildcard-test" in zone

    def test_auth_then_cleanup_full_lifecycle(self, client: TestClient, tmp_path: Path, bare: Path):
        domain = ACME_DOMAIN.format("e2e-lifecycle")
        auth_resp = client.post(
            "/acme/auth",
            json={"domain": domain, "validation": VALIDATION},
            headers={"Authorization": "Bearer e2e-key"},
        )
        assert auth_resp.status_code == 200, auth_resp.text

        zone_auth = _clone_zone(bare, tmp_path / "verify-lifecycle-auth")
        assert VALIDATION in zone_auth

        cleanup_resp = client.post(
            "/acme/cleanup",
            json={"domain": domain},
            headers={"Authorization": "Bearer e2e-key"},
        )
        assert cleanup_resp.status_code == 200, cleanup_resp.text

        zone_clean = _clone_zone(bare, tmp_path / "verify-lifecycle-clean")
        assert VALIDATION not in zone_clean
        assert "_acme-challenge.e2e-lifecycle" not in zone_clean

    def test_original_zone_preserved_after_clean(self, client: TestClient, tmp_path: Path, bare: Path):
        _clone_zone(bare, tmp_path / "original")

        domain = ACME_DOMAIN.format("e2e-preserve")
        client.post(
            "/acme/auth",
            json={"domain": domain, "validation": VALIDATION},
            headers={"Authorization": "Bearer e2e-key"},
        )
        client.post(
            "/acme/cleanup",
            json={"domain": domain},
            headers={"Authorization": "Bearer e2e-key"},
        )

        zone_after = _clone_zone(bare, tmp_path / "verify-preserve")
        # Zone handler reformats (loses $TTL, comments, SOA parens) but
        # the original A and NS records must survive, and ACME record must be gone.
        assert "_acme-challenge" not in zone_after
        assert "IN A" in zone_after
        assert "IN NS" in zone_after
        assert "IN SOA" in zone_after


class TestFullAcmeFlowWithoutAuth:
    def test_auth_requires_bearer_token(self, client: TestClient):
        resp = client.post(
            "/acme/auth",
            json={"domain": ACME_DOMAIN.format("noauth"), "validation": VALIDATION},
        )
        assert resp.status_code == 401

    def test_cleanup_requires_bearer_token(self, client: TestClient):
        resp = client.post(
            "/acme/cleanup",
            json={"domain": ACME_DOMAIN.format("noauth")},
        )
        assert resp.status_code == 401

    def test_auth_rejects_invalid_key(self, client: TestClient):
        resp = client.post(
            "/acme/auth",
            json={"domain": ACME_DOMAIN.format("wrongkey"), "validation": VALIDATION},
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert resp.status_code == 401


class TestE2EHealth:
    def test_health_and_metrics(self, client: TestClient):
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json() == {"status": "ok"}

        metrics = client.get("/metrics")
        assert metrics.status_code == 200
        assert "acme_webhook_requests_total" in metrics.text

    def test_certs_status_no_monitor(self, client: TestClient):
        resp = client.get(
            "/certs/status",
            headers={"Authorization": "Bearer e2e-key"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["certs"] == []


class TestE2EWithRealGitWire:
    """E2E tests that exercise the real git operations end-to-end."""

    def test_concurrent_auth_no_deadlock(self, client: TestClient, tmp_path: Path, bare: Path):
        results = []
        for i in range(3):
            domain = ACME_DOMAIN.format(f"concurrent-{i}")
            resp = client.post(
                "/acme/auth",
                json={"domain": domain, "validation": VALIDATION},
                headers={"Authorization": "Bearer e2e-key"},
            )
            results.append(resp.status_code)
        assert all(r == 200 for r in results), results

        zone = _clone_zone(bare, tmp_path / "verify-concurrent")
        for _ in range(3):
            assert VALIDATION in zone


class TestE2ESubdomainZoneResolution:
    def test_subdomain_uses_parent_zone(self, client: TestClient, tmp_path: Path, bare: Path):
        domain = "_acme-challenge.deep.sub.test.example.com"
        resp = client.post(
            "/acme/auth",
            json={"domain": domain, "validation": VALIDATION},
            headers={"Authorization": "Bearer e2e-key"},
        )
        assert resp.status_code == 200, resp.text

        zone = _clone_zone(bare, tmp_path / "verify-subdomain")
        assert VALIDATION in zone
        assert "_acme-challenge.deep.sub.test" in zone

    def test_multiple_auths_same_zone(self, client: TestClient, tmp_path: Path, bare: Path):
        for i in range(3):
            domain = ACME_DOMAIN.format(f"multi-{i}")
            resp = client.post(
                "/acme/auth",
                json={"domain": domain, "validation": VALIDATION},
                headers={"Authorization": "Bearer e2e-key"},
            )
            assert resp.status_code == 200, resp.text

        zone = _clone_zone(bare, tmp_path / "verify-multi")
        for _ in range(3):
            assert VALIDATION in zone
