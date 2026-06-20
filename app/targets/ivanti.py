from __future__ import annotations

import base64
import logging
from pathlib import Path

import httpx

from app.config import IvantiTargetConfig
from app.targets._crypto import pem_to_pfx
from app.targets.base import DeployResult, DeployTarget

logger = logging.getLogger(__name__)


def _read_api_key(path: str) -> str:
    p = Path(path)
    if not p.exists():
        logger.error("Ivanti API key file not found: %s", path)
        raise RuntimeError("Ivanti API key file not found")
    key = p.read_text().strip()
    if not key:
        logger.error("Ivanti API key file is empty: %s", path)
        raise RuntimeError("Ivanti API key file is empty")
    return key


class IvantiTarget(DeployTarget):
    """Deploy certificates to Ivanti Connect Secure (VPN) via REST API.

    Converts the PEM certificate to PFX with a random password and
    uploads it to the Ivanti device-certificates endpoint. The PFX
    password is regenerated on each deployment and never stored.
    """

    provider_type = "ivanti"

    def __init__(self, config: IvantiTargetConfig) -> None:
        self.name = config.name
        self.timeout = config.timeout
        self._config = config
        self._api_key: str | None = None
        self._client: httpx.Client | None = None

    def _ensure_client(self) -> httpx.Client:
        if self._client is None:
            if self._api_key is None:
                self._api_key = _read_api_key(self._config.api_key_path)
            self._client = httpx.Client(
                base_url=self._config.addr,
                headers={"Authorization": f"Bearer {self._api_key}"},
                verify=self._config.verify,
                timeout=self.timeout,
            )
        return self._client

    def deploy(
        self,
        domain: str,
        fullchain_pem: str,
        privkey_pem: str,
    ) -> DeployResult:
        try:
            pfx_bytes, password = pem_to_pfx(fullchain_pem, privkey_pem)
            pfx_b64 = base64.b64encode(pfx_bytes).decode()

            payload = {
                "cert": pfx_b64,
                "password": password,
                "internalPorts": self._config.internal_ports,
                "externalPorts": self._config.external_ports,
                "managementInterface": self._config.management_interface,
            }

            client = self._ensure_client()
            r = client.post(
                "/api/v1/system/certificates/device-certificates",
                json=payload,
            )
            r.raise_for_status()
            logger.info("Ivanti: deployed cert for %s to %s", domain, self._config.addr)
            return DeployResult(
                target=self.name,
                provider=self.provider_type,
                status="ok",
                details={
                    "host": self._config.addr,
                    "internal_ports": self._config.internal_ports,
                    "external_ports": self._config.external_ports,
                },
            )
        except Exception as e:
            logger.error("Ivanti: deploy failed for %s: %s", domain, e)
            return DeployResult(
                target=self.name,
                provider=self.provider_type,
                status="error",
                error=str(e),
            )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None
