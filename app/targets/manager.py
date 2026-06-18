from __future__ import annotations

import logging
from typing import get_args

from app.config import F5TargetConfig, TargetConfig
from app.targets.base import DeployResult, DeployTarget

logger = logging.getLogger(__name__)


def _build_target(cfg: TargetConfig) -> DeployTarget:
    """Instantiate the correct DeployTarget subclass based on provider."""
    if cfg.provider == "f5":
        from app.targets.f5 import F5Target
        return F5Target(cfg)
    if cfg.provider == "ivanti":
        from app.targets.ivanti import IvantiTarget
        return IvantiTarget(cfg)
    if cfg.provider == "exchange":
        from app.targets.exchange import ExchangeTarget
        return ExchangeTarget(cfg)
    msg = f"Unknown target provider: {cfg.provider}"
    raise ValueError(msg)


class DeployManager:
    """Orchestrate certificate deployment across multiple targets.

    Reads the list of configured targets, builds the appropriate
    DeployTarget instances, and exposes a ``deploy`` method that
    can target a subset by name.
    """

    def __init__(self, target_configs: list[TargetConfig]) -> None:
        self._targets: dict[str, DeployTarget] = {}
        for cfg in target_configs:
            t = _build_target(cfg)
            if t.name in self._targets:
                logger.warning(
                    "Duplicate target name %r — keeping the last definition",
                    t.name,
                )
            self._targets[t.name] = t

    @property
    def targets(self) -> dict[str, DeployTarget]:
        """Return a read-only view of registered targets (name → instance)."""
        return dict(self._targets)

    def get(self, name: str) -> DeployTarget | None:
        """Return a single target by name, or *None*."""
        return self._targets.get(name)

    def deploy(
        self,
        domain: str,
        fullchain_pem: str,
        privkey_pem: str,
        target_names: list[str] | None = None,
    ) -> list[DeployResult]:
        """Deploy a certificate to every target (or a named subset).

        Args:
            domain: The domain name (e.g. ``example.com``).
            fullchain_pem: PEM-encoded full certificate chain.
            privkey_pem: PEM-encoded private key.
            target_names: Optional list of target names to restrict
                deployment to.  *None* means every registered target.

        Returns:
            A list of DeployResult, one per target.
        """
        if target_names is None:
            targets = list(self._targets.values())
        else:
            targets = [self._targets[n] for n in target_names]

        results: list[DeployResult] = []
        for t in targets:
            try:
                result = t.deploy(domain, fullchain_pem, privkey_pem)
                results.append(result)
            except Exception as e:
                logger.error("Deploy to %s failed: %s", t.name, e)
                results.append(
                    DeployResult(
                        target=t.name,
                        provider=t.provider_type,
                        status="error",
                        error=str(e),
                    )
                )
        return results

    def close(self) -> None:
        """Release resources on every registered target."""
        for t in self._targets.values():
            try:
                t.close()
            except Exception:
                logger.exception("Error while closing target %s", t.name)
