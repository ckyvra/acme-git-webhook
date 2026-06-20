"""Prometheus metrics instrumentation for cert-renew."""

from prometheus_client import Counter, Gauge, make_asgi_app

# ── Application-level counters ──────────────────────────────────────

cert_auth_total = Counter(
    "acme_cert_auth_total",
    "Total number of ACME auth (challenge-add) operations",
)

cert_cleanup_total = Counter(
    "acme_cert_cleanup_total",
    "Total number of ACME cleanup (challenge-remove) operations",
)

cert_deploy_total = Counter(
    "acme_cert_deploy_total",
    "Total number of ACME deploy operations",
    labelnames=["target"],
)

cert_renew_total = Counter(
    "acme_cert_renew_total",
    "Total number of manual certificate renewals",
)

webhook_requests_total = Counter(
    "acme_webhook_requests_total",
    "Total number of HTTP requests by endpoint",
    labelnames=["endpoint", "method", "status"],
)

# ── Certificate-level gauges ────────────────────────────────────────

cert_expiry_days_left = Gauge(
    "acme_cert_expiry_days_left",
    "Number of days until certificate expiration",
    labelnames=["domain"],
)

cert_expiry_timestamp = Gauge(
    "acme_cert_expiry_timestamp",
    "Unix timestamp of certificate expiry",
    labelnames=["domain"],
)

cert_not_before_timestamp = Gauge(
    "acme_cert_not_before_timestamp",
    "Unix timestamp of certificate validity start",
    labelnames=["domain"],
)

cert_info = Gauge(
    "acme_cert_info",
    "Static info about each tracked certificate",
    labelnames=["domain", "stored_at"],
)

cert_last_renewal_timestamp = Gauge(
    "acme_cert_last_renewal_timestamp",
    "Unix timestamp of the last renewal attempt",
    labelnames=["domain", "status"],
)

cert_renewal_count = Counter(
    "acme_cert_renewal_count",
    "Total number of renewals per domain",
    labelnames=["domain"],
)

certs_total = Gauge(
    "acme_certs_total",
    "Number of certificates tracked by status",
    labelnames=["status"],
)


def clear_cert_metrics(domains: set[str]) -> None:
    """Remove Prometheus metrics for domains no longer tracked."""
    for domain in domains:
        cert_expiry_days_left.remove(domain)
        cert_expiry_timestamp.remove(domain)
        cert_not_before_timestamp.remove(domain)
        cert_info.remove(domain, "")
        cert_last_renewal_timestamp.remove(domain, "success")
        cert_last_renewal_timestamp.remove(domain, "failure")
        cert_renewal_count.remove(domain)


def create_metrics_app():
    """Return an ASGI app exposing Prometheus metrics at ``/metrics``."""
    return make_asgi_app()
