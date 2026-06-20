from __future__ import annotations

import logging
from pathlib import Path

import httpx

from app.config import F5TargetConfig
from app.targets.base import DeployResult, DeployTarget

logger = logging.getLogger(__name__)

BIGIP_API_BASE = "/mgmt/tm"
REQUEST_TIMEOUT = 30.0


def sanitize_name(domain: str) -> str:
    """Replace wildcard prefix for use in F5 object names."""
    return domain.replace("*", "wildcard")


def read_password(path: str) -> str:
    """Read a plain-text password from a mounted file."""
    p = Path(path)
    if not p.exists():
        logger.error("F5 password file not found: %s", path)
        raise RuntimeError("F5 password file not found")
    pw = p.read_text().strip()
    if not pw:
        logger.error("F5 password file is empty: %s", path)
        raise RuntimeError("F5 password file is empty")
    return pw


class F5Target(DeployTarget):
    """Deploy certificates to a single F5 Big-IP via iControl REST.

    The target uploads the PEM fullchain + private key, then scans
    existing Client SSL profiles whose cert reference contains the
    target domain (or its sanitised wildcard equivalent) and updates
    each profile with the new certificate.
    """

    provider_type = "f5"

    def __init__(self, config: F5TargetConfig) -> None:
        self.name = config.name
        self.timeout = config.timeout
        self._config = config
        self._password: str | None = None
        self._client: httpx.Client | None = None

    # --- internal HTTP helpers ------------------------------------------------

    def _ensure_client(self) -> httpx.Client:
        if self._client is None:
            if self._password is None:
                self._password = read_password(self._config.password_path)
            self._client = httpx.Client(
                base_url=self._config.addr,
                auth=(self._config.username, self._password),
                verify=self._config.verify,
                timeout=self.timeout,
            )
        return self._client

    def _api_post(self, path: str, json_data: dict) -> dict:
        client = self._ensure_client()
        r = client.post(f"{BIGIP_API_BASE}/{path}", json=json_data)
        r.raise_for_status()
        return r.json()

    def _api_put(self, path: str, json_data: dict) -> dict:
        client = self._ensure_client()
        r = client.put(f"{BIGIP_API_BASE}/{path}", json=json_data)
        r.raise_for_status()
        return r.json()

    def _api_get(self, path: str) -> dict:
        client = self._ensure_client()
        r = client.get(f"{BIGIP_API_BASE}/{path}")
        r.raise_for_status()
        return r.json()

    # --- F5 operations --------------------------------------------------------

    def _upload_cert(self, name: str, fullchain_pem: str) -> str:
        full_name = f"/Common/{name}"
        self._api_post(
            "sys/file/ssl-cert",
            {"name": full_name, "content": fullchain_pem},
        )
        logger.info("F5: uploaded SSL cert %s to %s", name, self._config.addr)
        return full_name

    def _upload_key(self, name: str, privkey_pem: str) -> str:
        full_name = f"/Common/{name}"
        self._api_post(
            "sys/file/ssl-key",
            {"name": full_name, "content": privkey_pem},
        )
        logger.info("F5: uploaded SSL key %s to %s", name, self._config.addr)
        return full_name

    def _find_ssl_profiles_for_domain(self, domain: str) -> list[str]:
        try:
            resp = self._api_get("ltm/profile/client-ssl?$select=name,cert,key")
        except Exception:
            logger.warning("F5: failed to list SSL profiles on %s", self._config.addr)
            return []
        profiles = []
        sanitized = sanitize_name(domain).lower()
        for item in resp.get("items", []):
            cert_ref = (item.get("cert") or "").lower()
            if domain.lower() in cert_ref or sanitized in cert_ref or cert_ref == "none":
                profiles.append(item["name"])
        return profiles

    def _update_profile_cert(self, profile_name: str, cert_name: str, key_name: str) -> None:
        partition = "Common"
        full_path = f"ltm/profile/client-ssl/{partition}/{profile_name.replace('/', '~')}"
        self._api_put(full_path, {"cert": cert_name, "key": key_name})
        logger.info(
            "F5: updated profile %s with cert %s on %s",
            profile_name,
            cert_name,
            self._config.addr,
        )

    # --- public API -----------------------------------------------------------

    def deploy(
        self,
        domain: str,
        fullchain_pem: str,
        privkey_pem: str,
    ) -> DeployResult:
        """Upload the certificate and update matching SSL profiles."""
        name = sanitize_name(domain)
        cert_name = self._upload_cert(name, fullchain_pem)
        key_name = self._upload_key(name, privkey_pem)

        profiles = self._find_ssl_profiles_for_domain(domain)
        if not profiles:
            logger.warning(
                "F5: no SSL profiles found for domain %s on %s",
                domain,
                self._config.addr,
            )
            return DeployResult(
                target=self.name,
                provider=self.provider_type,
                status="ok",
                details={
                    "host": self._config.addr,
                    "cert_name": cert_name,
                    "key_name": key_name,
                    "updated_profiles": [],
                },
            )

        for profile in profiles:
            self._update_profile_cert(profile, cert_name, key_name)

        return DeployResult(
            target=self.name,
            provider=self.provider_type,
            status="ok",
            details={
                "host": self._config.addr,
                "cert_name": cert_name,
                "key_name": key_name,
                "updated_profiles": profiles,
            },
        )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
