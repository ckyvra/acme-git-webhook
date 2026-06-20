from __future__ import annotations

import json
import logging
import shlex
import subprocess
from datetime import UTC, datetime

import httpx
from apscheduler.schedulers.background import BackgroundScheduler

from app.config import MonitorConfig, OpensslConfig, is_within_window, next_window_start
from app.metrics import (
    cert_expiry_days_left,
    cert_expiry_timestamp,
    cert_info,
    cert_last_renewal_timestamp,
    cert_not_before_timestamp,
    cert_renewal_count,
    certs_total,
)
from app.vault_handler import VaultHandler

logger = logging.getLogger(__name__)

WEBHOOK_TIMEOUT = 15.0


class CertMonitor:
    def __init__(
        self,
        config: MonitorConfig | None,
        vault_handler: VaultHandler | None,
        openssl: OpensslConfig | None = None,
    ) -> None:
        self.config = config
        self._vault = vault_handler
        self._openssl = openssl
        self._scheduler: BackgroundScheduler | None = None
        self._sent_warnings: dict[str, set[int]] = {}
        self._latest_status: list[dict] = []
        self._renewing: set[str] = set()

    def _load_certs_from_vault(self) -> list[dict]:
        if self._vault is None:
            return []
        try:
            self._vault._ensure_authenticated()
            client = self._vault._client
            if client is None:
                raise RuntimeError("Vault client not available")
            mount = self._vault.config.kv_mount
            path = self._vault.config.certs_path
            domains = client.secrets.kv.v2.list_secrets(mount_point=mount, path=path)
        except Exception:
            logger.warning("CertMonitor: no certificates found in Vault", exc_info=True)
            return []

        certs = []
        for domain_key in domains.get("data", {}).get("keys", []):
            domain = domain_key.rstrip("/")
            try:
                secret = client.secrets.kv.v2.read_secret_version(mount_point=mount, path=f"{path}/{domain}")
                data = secret.get("data", {}).get("data", {})
                metadata_raw = data.get("metadata", "{}")
                metadata = json.loads(metadata_raw) if isinstance(metadata_raw, str) else metadata_raw
                expiry_str = metadata.get("expiry")
                if expiry_str and expiry_str != "unknown":
                    expiry = datetime.fromisoformat(expiry_str)
                    days_left = (expiry - datetime.now(UTC)).days
                else:
                    expiry = None
                    days_left = None
                certs.append(
                    {
                        "domain": domain,
                        "expiry": expiry.isoformat() if expiry else None,
                        "days_left": days_left,
                        "stored_at": metadata.get("stored_at"),
                        "metadata": metadata,
                    }
                )
            except Exception:
                logger.warning("CertMonitor: failed to read cert for %s", domain, exc_info=True)
        return certs

    def _send_webhook_alert(self, domain: str, days_left: int) -> None:
        if self.config is None:
            return
        url = self.config.alert_webhook_url
        if not url:
            return
        try:
            payload = {
                "text": (f"Certificate expiration warning: {domain}\nDays left: {days_left}\nSeverity: {'CRITICAL' if days_left <= 7 else 'WARNING' if days_left <= 30 else 'INFO'}"),
                "domain": domain,
                "days_left": days_left,
            }
            httpx.post(url, json=payload, timeout=WEBHOOK_TIMEOUT)
        except Exception:
            logger.warning("CertMonitor: failed to send webhook alert for %s", domain, exc_info=True)

    def _run_renew(self, domain: str) -> None:
        if self.config is None or not self.config.renew_command:
            return  # lgtm[py/clear-text-logging-sensitive-data]

        window = self.config.deploy_window
        if window and self._scheduler is not None:
            now = datetime.now(UTC)
            if not is_within_window(window, now):
                next_time = next_window_start(window, now)
                logger.info(
                    "CertMonitor: deferring renew for %s until %s (window %s-%s %s)",
                    domain,
                    next_time,
                    window.start,
                    window.end,
                    window.timezone,
                )
                self._scheduler.add_job(
                    self._run_renew,
                    trigger="date",
                    run_date=next_time,
                    args=[domain],
                    id=f"renew-{domain}",
                    replace_existing=True,
                )
                return

        cmd = self.config.renew_command.replace("{domain}", domain)
        openssl = self._openssl
        if openssl:
            cmd = cmd.replace("{key_type}", openssl.key_algorithm)
            cmd = cmd.replace("{key_size}", str(openssl.rsa_key_size))
            cmd = cmd.replace("{curve}", openssl.ecdsa_curve)
            cmd = cmd.replace("{sig_hash}", openssl.signature_hash)
        now_ts = datetime.now(UTC).timestamp()
        logger.info(  # lgtm[py/clear-text-logging-sensitive-data]
            "CertMonitor: renewing %s via %s", domain, cmd
        )
        try:
            result = subprocess.run(  # noqa: S603 — cmd is assembled from config, not user input
                shlex.split(cmd),
                timeout=self.config.renew_timeout,
                capture_output=True,
                text=True,
                check=True,
            )
            cert_last_renewal_timestamp.labels(domain=domain, status="success").set(now_ts)
            cert_renewal_count.labels(domain=domain).inc()
            logger.info(  # lgtm[py/clear-text-logging-sensitive-data]
                "CertMonitor: renewal succeeded for %s (rc=%d)",
                domain,
                result.returncode,
            )
        except subprocess.TimeoutExpired:
            cert_last_renewal_timestamp.labels(domain=domain, status="failure").set(now_ts)
            logger.error(  # lgtm[py/clear-text-logging-sensitive-data]
                "CertMonitor: renewal timed out for %s", domain
            )
        except subprocess.CalledProcessError as e:
            cert_last_renewal_timestamp.labels(domain=domain, status="failure").set(now_ts)
            logger.error(  # lgtm[py/clear-text-logging-sensitive-data]
                "CertMonitor: renewal failed for %s (rc=%d)",
                domain,
                e.returncode,
            )

    def _should_renew_by_percentage(self, domain: str, days_left: int, metadata: dict | None) -> bool:
        if self.config is None:
            return False
        pct = self.config.renew_percentage
        if pct is None or metadata is None:
            return False
        not_before = metadata.get("not_before")
        expiry = metadata.get("expiry")
        if not not_before or not expiry or not_before == "unknown" or expiry == "unknown":
            return False
        try:
            total = (datetime.fromisoformat(expiry) - datetime.fromisoformat(not_before)).days
            if total <= 0:
                return False
            return days_left / total * 100 <= pct
        except (ValueError, TypeError):
            return False

    def _check_day_threshold(self, domain: str, days_left: int, metadata: dict | None = None) -> None:
        if self.config is None:
            return
        for threshold in self.config.warn_days:
            if days_left <= threshold:
                sent = self._sent_warnings.setdefault(domain, set())
                if threshold not in sent:
                    logger.warning(  # lgtm[py/clear-text-logging-sensitive-data] — operational, not secret
                        "CertMonitor: %s expires in %d days (threshold: %d)",
                        domain,
                        days_left,
                        threshold,
                    )
                    self._send_webhook_alert(domain, days_left)
                    sent.add(threshold)

        should_renew = days_left <= self.config.renew_threshold or self._should_renew_by_percentage(domain, days_left, metadata)
        if self.config.renew_command and should_renew and domain not in self._renewing:
            self._renewing.add(domain)
            self._run_renew(domain)

    def run_check(self) -> list[dict]:
        certs = self._load_certs_from_vault()
        for cert in certs:
            domain = cert["domain"]
            days = cert.get("days_left")
            if days is not None and self.config is not None:
                self._check_day_threshold(domain, days, metadata=cert.get("metadata"))
            cert_expiry_days_left.labels(domain=domain).set(days or -1)
            expiry_str = cert.get("expiry")
            if expiry_str:
                cert_expiry_timestamp.labels(domain=domain).set(datetime.fromisoformat(expiry_str).timestamp())
            else:
                cert_expiry_timestamp.labels(domain=domain).set(-1)
            metadata = cert.get("metadata") or {}
            not_before = metadata.get("not_before")
            if not_before and not_before != "unknown":
                cert_not_before_timestamp.labels(domain=domain).set(datetime.fromisoformat(not_before).timestamp())
            stored_at = cert.get("stored_at") or ""
            cert_info.labels(domain=domain, stored_at=stored_at).set(1)
        self._latest_status = certs
        statuses = {"valid": 0, "warning": 0, "critical": 0, "expired": 0}
        for cert in certs:
            days = cert.get("days_left")
            if days is None:
                statuses["expired"] += 1
            elif days <= 0:
                statuses["expired"] += 1
            elif days <= 14:
                statuses["critical"] += 1
            elif days <= 60:
                statuses["warning"] += 1
            else:
                statuses["valid"] += 1
        for status, count in statuses.items():
            certs_total.labels(status=status).set(count)
        logger.info("CertMonitor: checked %d certificates", len(certs))
        return certs

    def get_status(self) -> list[dict]:
        return self._latest_status

    def start(self) -> None:
        if self.config is None:
            logger.info("CertMonitor: monitoring disabled (no config)")
            return
        self._scheduler = BackgroundScheduler()
        self._scheduler.add_job(
            self.run_check,
            "interval",
            hours=self.config.check_interval_hours,
            id="cert_monitor_check",
        )
        self._scheduler.start()
        self.run_check()
        logger.info(
            "CertMonitor: started (interval=%dh)",
            self.config.check_interval_hours,
        )

    def stop(self) -> None:
        if self._scheduler is not None:
            self._scheduler.shutdown(wait=False)
            self._scheduler = None
