"""Vault integration for secure certificate storage.

Provides a VaultHandler class that authenticates via AppRole and
stores Let's Encrypt certificate material in HashiCorp Vault's KV
secrets engine.

Usage::

    handler = VaultHandler(config)
    handler.store_cert("example.com", cert_pem, chain_pem,
                       fullchain_pem, privkey_pem)
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone

import hvac
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from app.config import VaultConfig

logger = logging.getLogger(__name__)


def _extract_expiry(cert_pem: str) -> str | None:
    """Parse the notAfter date from a PEM certificate.

    Args:
        cert_pem: PEM-encoded X.509 certificate.

    Returns:
        ISO-8601 formatted expiry string (e.g. "2026-09-15T00:00:00+00:00"),
        or None if parsing fails.
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        return cert.not_valid_after_utc.isoformat()
    except Exception:
        logger.warning("Failed to parse certificate expiry", exc_info=True)
        return None


def _extract_not_before(cert_pem: str) -> str | None:
    """Parse the notBefore date from a PEM certificate.

    Args:
        cert_pem: PEM-encoded X.509 certificate.

    Returns:
        ISO-8601 formatted notBefore string, or None if parsing fails.
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        return cert.not_valid_before_utc.isoformat()
    except Exception:
        logger.warning("Failed to parse certificate notBefore", exc_info=True)
        return None


class VaultHandler:
    """Handles authentication to Vault and certificate storage operations.

    Authenticates via AppRole, caching the token locally and
    refreshing it automatically when it expires. All Vault write
    operations target the KV secrets engine at the configured mount
    path.

    Attributes:
        config: The VaultConfig instance loaded from config.yaml.
        _client: An authenticated hvac.Client instance (or None).
        _token_expires_at: Unix timestamp after which the current
            token should be refreshed.
    """

    def __init__(self, config: VaultConfig) -> None:
        """Initialise the handler with the Vault configuration.

        Does NOT authenticate immediately — authentication happens
        lazily on the first operation.

        Args:
            config: Validated Vault configuration.
        """
        self.config = config
        self._client: hvac.Client | None = None
        self._token_expires_at: float = 0.0

    def _read_secret_id(self) -> str:
        """Read the AppRole SecretID from the configured file path.

        Using a file-based secret avoids embedding the SecretID in
        the YAML configuration file, reducing the risk of accidental
        exposure in version control.

        Returns:
            The SecretID string.

        Raises:
            FileNotFoundError: If the secret_id_path does not exist.
            RuntimeError: If the file is empty.
        """
        path = self.config.secret_id_path
        with open(path) as f:
            secret_id = f.read().strip()
        if not secret_id:
            raise RuntimeError(f"SecretID file {path} is empty")
        return secret_id

    def _authenticate(self) -> None:
        """Authenticate to Vault via AppRole and store the client token.

        Creates a new hvac.Client pointed at the configured Vault
        address, performs an AppRole login, and stores the resulting
        token along with its expiry time. This method is called
        automatically by ``_ensure_authenticated``.

        Raises:
            hvac.exceptions.VaultError: If authentication fails
                (wrong credentials, network error, etc.).
        """
        client = hvac.Client(
            url=self.config.addr,
            verify=self.config.verify,
        )
        secret_id = self._read_secret_id()
        login_result = client.auth.approle.login(
            role_id=self.config.role_id,
            secret_id=secret_id,
        )

        # Extract the token and lease duration from the login response.
        # The client is garbage collected and recreated each time to
        # avoid stale connection pools.
        self._client = hvac.Client(
            url=self.config.addr,
            token=login_result["auth"]["client_token"],
            verify=self.config.verify,
        )
        lease_duration = login_result["auth"].get("lease_duration", 3600)
        # Renew slightly before expiry (80% of the lease duration) to
        # avoid race conditions.
        self._token_expires_at = time.time() + lease_duration * 0.8

    def _ensure_authenticated(self) -> None:
        """Ensure the client has a valid, non-expired token.

        If the token is missing or expired (or within the renewal
        margin), a fresh AppRole login is performed.

        Raises:
            hvac.exceptions.VaultError: If authentication fails.
            FileNotFoundError: If the SecretID file is missing.
        """
        if self._client is None or time.time() >= self._token_expires_at:
            logger.info("Vault token missing or expired, re-authenticating")
            self._authenticate()
            logger.info("Vault AppRole authentication successful")

    def store_cert(
        self,
        domain: str,
        cert_pem: str,
        chain_pem: str | None,
        fullchain_pem: str,
        privkey_pem: str,
    ) -> str:
        """Store a certificate and its private key in Vault KV.

        Writes the PEM files under ``<kv_mount>/<certs_path>/<domain>/``::

            <kv_mount>/<certs_path>/<domain>/cert.pem
            <kv_mount>/<certs_path>/<domain>/chain.pem
            <kv_mount>/<certs_path>/<domain>/fullchain.pem
            <kv_mount>/<certs_path>/<domain>/privkey.pem
            <kv_mount>/<certs_path>/<domain>/metadata

        Args:
            domain: The domain name (e.g. ``example.com``).
            cert_pem: PEM-encoded leaf certificate.
            chain_pem: PEM-encoded chain (may be None).
            fullchain_pem: PEM-encoded full chain (cert + chain).
            privkey_pem: PEM-encoded private key.

        Returns:
            The full Vault path where the certificate was stored
            (e.g. ``secret/certs/example.com``).

        Raises:
            hvac.exceptions.VaultError: If the Vault write fails.
            FileNotFoundError: If the SecretID file is missing.
            RuntimeError: If the SecretID file is empty.
        """
        self._ensure_authenticated()

        base_path = f"{self.config.kv_mount}/{self.config.certs_path}/{domain}"

        # Build metadata about the certificate.
        expiry = _extract_expiry(cert_pem)
        not_before = _extract_not_before(cert_pem)
        metadata = {
            "domain": domain,
            "issuer": "Let's Encrypt",
            "stored_at": datetime.now(timezone.utc).isoformat(),
            "not_before": not_before or "unknown",
            "expiry": expiry or "unknown",
        }

        # Write each component as a separate secret. The KV store in
        # Vault supports multiple key-value pairs per path, so all
        # PEM files go under the same logical path.
        self._client.secrets.kv.v2.create_or_update_secret(
            mount_point=self.config.kv_mount,
            path=f"{self.config.certs_path}/{domain}",
            secret={
                "cert.pem": cert_pem,
                "chain.pem": chain_pem or "",
                "fullchain.pem": fullchain_pem,
                "privkey.pem": privkey_pem,
                "metadata": json.dumps(metadata, indent=2),
            },
        )

        logger.info("Certificate for %s stored in Vault at %s", domain, base_path)
        return base_path

    def delete_cert(self, domain: str) -> bool:
        """Delete a certificate entry from Vault.

        Removes the entire path ``<kv_mount>/<certs_path>/<domain>``
        including all its metadata and PEM files.

        Args:
            domain: The domain name to delete.

        Returns:
            True if the deletion succeeded (or the path did not
            exist), False on unexpected errors.

        Raises:
            hvac.exceptions.VaultError: If the Vault operation fails.
        """
        self._ensure_authenticated()

        try:
            self._client.secrets.kv.v2.delete_metadata_and_all_versions(
                mount_point=self.config.kv_mount,
                path=f"{self.config.certs_path}/{domain}",
            )
            logger.info("Certificate for %s deleted from Vault", domain)
            return True
        except hvac.exceptions.InvalidPath:
            # Path did not exist — nothing to delete.
            logger.info("No Vault path found for %s, skipping delete", domain)
            return True
