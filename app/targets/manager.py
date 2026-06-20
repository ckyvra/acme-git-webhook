from __future__ import annotations

import logging
from datetime import UTC, datetime

from apscheduler.schedulers.background import BackgroundScheduler

from app.config import DeployWindow, TargetConfig, is_within_window, next_window_start
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

    def __init__(
        self,
        target_configs: list[TargetConfig],
        default_window: DeployWindow | None = None,
    ) -> None:
        self._targets: dict[str, DeployTarget] = {}
        self._windows: dict[str, DeployWindow | None] = {}
        self._scheduler = BackgroundScheduler()
        self._scheduler.start()
        for cfg in target_configs:
            t = _build_target(cfg)
            if t.name in self._targets:
                logger.warning(
                    "Duplicate target name %r — keeping the last definition",
                    t.name,
                )
            self._targets[t.name] = t
            self._windows[t.name] = cfg.deploy_window or default_window

    @property
    def targets(self) -> dict[str, DeployTarget]:
        """Return a read-only view of registered targets (name → instance)."""
        return dict(self._targets)

    def get(self, name: str) -> DeployTarget | None:
        """Return a single target by name, or *None*."""
        return self._targets.get(name)

    def _schedule_deferred(
        self,
        target_name: str,
        domain: str,
        fullchain_pem: str,
        privkey_pem: str,
        run_at: datetime,
    ) -> None:
        job_id = f"deploy-{target_name}-{domain}"
        self._scheduler.add_job(
            self._deferred_deploy,
            trigger="date",
            run_date=run_at,
            args=[target_name, domain, fullchain_pem, privkey_pem],
            id=job_id,
            replace_existing=True,
        )

    def _deferred_deploy(
        self,
        target_name: str,
        domain: str,
        fullchain_pem: str,
        privkey_pem: str,
    ) -> None:
        t = self._targets.get(target_name)
        if t is None:
            logger.warning("Deferred deploy: target %r no longer exists", target_name)
            return
        try:
            result = t.deploy(domain, fullchain_pem, privkey_pem)
            logger.info("Deferred deploy to %s completed: %s", target_name, result.status)
        except Exception as e:
            logger.error("Deferred deploy to %s failed: %s", target_name, e)

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

        now = datetime.now(UTC)
        results: list[DeployResult] = []
        for t in targets:
            window = self._windows.get(t.name)
            if window and not is_within_window(window, now):
                next_time = next_window_start(window, now)
                self._schedule_deferred(t.name, domain, fullchain_pem, privkey_pem, next_time)
                logger.info(
                    "Deploy to %s deferred until %s (outside window %s-%s %s)",
                    t.name,
                    next_time,
                    window.start,
                    window.end,
                    window.timezone,
                )
                results.append(
                    DeployResult(
                        target=t.name,
                        provider=t.provider_type,
                        status="deferred",
                        details={"next_window": next_time.isoformat()},
                    )
                )
                continue
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
        self._scheduler.shutdown(wait=False)
        for t in self._targets.values():
            try:
                t.close()
            except Exception:
                logger.exception("Error while closing target %s", t.name)
