from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Literal

from pydantic import BaseModel


class DeployResult(BaseModel):
    """Result of a deployment operation against a single target."""

    target: str
    provider: str
    status: Literal["ok", "error", "deferred"]
    details: dict = {}
    error: str | None = None


class DeployTarget(ABC):
    """Abstract base class for all certificate deployment targets.

    Each subclass implements the logic to push a certificate (PEM
    fullchain + private key) to a specific system — F5 Big-IP, Ivanti
    VPN, Exchange SMTP, etc.
    """

    name: str
    provider_type: str
    timeout: int

    @abstractmethod
    def deploy(
        self,
        domain: str,
        fullchain_pem: str,
        privkey_pem: str,
    ) -> DeployResult: ...

    def close(self) -> None:
        """Release any held resources (HTTP clients, etc.)."""
