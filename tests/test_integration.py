"""Integration tests requiring external infrastructure.

Run with::

    pytest --run-integration

or set the ``RUN_INTEGRATION`` environment variable.

Markers:
    integration: tests that require Docker, network, or other services.
"""

import subprocess
from pathlib import Path

import dns.resolver
import pytest

pytestmark = pytest.mark.integration


def _docker_available() -> bool:
    try:
        subprocess.run(
            ["docker", "info"],
            capture_output=True,
            check=True,
            timeout=10,
        )
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def _start_vault_dev() -> tuple[subprocess.Popen, str, str]:
    """Start a Vault dev server in Docker and return (process, addr, root_token)."""
    container_name = "acme-webhook-vault-dev"
    subprocess.run(
        ["docker", "rm", "-f", container_name],
        capture_output=True,
    )
    proc = subprocess.Popen(
        [
            "docker",
            "run",
            "--rm",
            "--name",
            container_name,
            "-p",
            "18200:8200",
            "-e",
            "VAULT_DEV_ROOT_TOKEN_ID=dev-root-token",
            "hashicorp/vault:latest",
            "server",
            "-dev",
            "-dev-listen-address=0.0.0.0:8200",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    addr = "http://localhost:18200"
    root_token = "dev-root-token"
    return proc, addr, root_token


class TestDnsIntegration:
    """Integration tests against public DNS resolvers."""

    KNOWN_TXT_DOMAIN = "google.com"
    EXPECTED_RECORD_PREFIX = "v=spf1"

    def test_resolve_known_txt_record(self):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        resolver.timeout = 5
        resolver.lifetime = 10

        answers = resolver.resolve(self.KNOWN_TXT_DOMAIN, "TXT")
        assert len(answers) > 0
        txt_strings = [str(r) for r in answers]
        assert any(self.EXPECTED_RECORD_PREFIX in t for t in txt_strings)

    def test_resolve_nxdomain(self):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8"]
        resolver.timeout = 5
        resolver.lifetime = 10

        with pytest.raises(dns.resolver.NXDOMAIN):
            resolver.resolve("this-domain-does-not-exist-12345.example.com", "A")


class TestVaultIntegration:
    """Integration tests against a Vault dev server in Docker."""

    @pytest.mark.skipif(not _docker_available(), reason="Docker not available")
    def test_store_and_read_secret(self, tmp_path: Path):
        proc, addr, root_token = _start_vault_dev()
        try:
            import hvac

            client = hvac.Client(url=addr, token=root_token)
            assert client.is_authenticated()

            secret_data = {
                "fullchain.pem": "chain-content",
                "privkey.pem": "key-content",
            }
            client.secrets.kv.v2.create_or_update_secret(
                mount_point="secret",
                path="certs/example.com",
                secret={"data": secret_data},
            )

            read = client.secrets.kv.v2.read_secret_version(
                mount_point="secret",
                path="certs/example.com",
            )
            assert read["data"]["data"]["fullchain.pem"] == "chain-content"
            assert read["data"]["data"]["privkey.pem"] == "key-content"

            client.secrets.kv.v2.delete_metadata_and_all_versions(
                mount_point="secret",
                path="certs/example.com",
            )

            with pytest.raises(hvac.exceptions.InvalidPath):
                client.secrets.kv.v2.read_secret_version(
                    mount_point="secret",
                    path="certs/example.com",
                )
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()

    @pytest.mark.skipif(not _docker_available(), reason="Docker not available")
    def test_vault_authentication_failure(self):
        proc, addr, root_token = _start_vault_dev()
        try:
            import hvac

            client = hvac.Client(url=addr, token="wrong-token")
            assert not client.is_authenticated()
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
