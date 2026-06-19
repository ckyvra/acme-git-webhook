from __future__ import annotations

import logging
from pathlib import Path

import httpx

from app.config import F5Config, F5HostConfig

logger = logging.getLogger(__name__)

BIGIP_API_BASE = "/mgmt/tm"
REQUEST_TIMEOUT = 30.0


def _sanitize_name(domain: str) -> str:
    return domain.replace("*", "wildcard")


def _read_password(path: str) -> str:
    p = Path(path)
    if not p.exists():
        raise RuntimeError(f"F5 password file not found: {path}")
    pw = p.read_text().strip()
    if not pw:
        raise RuntimeError(f"F5 password file is empty: {path}")
    return pw


class F5HostHandler:
    def __init__(self, config: F5HostConfig) -> None:
        self.config = config
        self._password: str | None = None
        self._client: httpx.Client | None = None

    def _ensure_client(self) -> httpx.Client:
        if self._client is None:
            if self._password is None:
                self._password = _read_password(self.config.password_path)
            self._client = httpx.Client(
                base_url=self.config.addr,
                auth=(self.config.username, self._password),
                verify=self.config.verify,
                timeout=REQUEST_TIMEOUT,
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

    def _upload_cert(self, name: str, cert_pem: str) -> str:
        full_name = f"/Common/{name}"
        self._api_post(
            "sys/file/ssl-cert",
            {"name": full_name, "content": cert_pem},
        )
        logger.info("F5: uploaded SSL cert %s to %s", name, self.config.addr)
        return full_name

    def _upload_key(self, name: str, key_pem: str) -> str:
        full_name = f"/Common/{name}"
        self._api_post(
            "sys/file/ssl-key",
            {"name": full_name, "content": key_pem},
        )
        logger.info("F5: uploaded SSL key %s to %s", name, self.config.addr)
        return full_name

    def _find_ssl_profiles_for_domain(self, domain: str) -> list[str]:
        try:
            resp = self._api_get("ltm/profile/client-ssl?$select=name,cert,key")
        except Exception:
            logger.warning("F5: failed to list SSL profiles on %s", self.config.addr)
            return []
        profiles = []
        sanitized = _sanitize_name(domain).lower()
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
            self.config.addr,
        )

    def deploy_cert(
        self,
        domain: str,
        cert_pem: str,
        fullchain_pem: str,
        privkey_pem: str,
    ) -> dict:
        name = _sanitize_name(domain)
        cert_name = self._upload_cert(name, fullchain_pem)
        key_name = self._upload_key(name, privkey_pem)

        profiles = self._find_ssl_profiles_for_domain(domain)
        if not profiles:
            logger.warning(
                "F5: no SSL profiles found for domain %s on %s",
                domain,
                self.config.addr,
            )
            return {
                "host": self.config.addr,
                "cert_name": cert_name,
                "key_name": key_name,
                "updated_profiles": [],
            }

        for profile in profiles:
            self._update_profile_cert(profile, cert_name, key_name)

        return {
            "host": self.config.addr,
            "cert_name": cert_name,
            "key_name": key_name,
            "updated_profiles": profiles,
        }

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None


class F5Handler:
    def __init__(self, config: F5Config) -> None:
        self._hosts = [F5HostHandler(h) for h in config.hosts]

    def deploy_cert(
        self,
        domain: str,
        cert_pem: str,
        fullchain_pem: str,
        privkey_pem: str,
    ) -> list[dict]:
        results = []
        for host in self._hosts:
            try:
                result = host.deploy_cert(domain, cert_pem, fullchain_pem, privkey_pem)
                result["status"] = "ok"
                results.append(result)
            except Exception as e:
                logger.error("F5: deployment failed for %s: %s", host.config.addr, e)
                results.append(
                    {
                        "host": host.config.addr,
                        "status": "error",
                        "error": str(e),
                    }
                )
        return results

    def close(self) -> None:
        for host in self._hosts:
            host.close()
