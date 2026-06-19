# Certificate expiration monitoring

The certificate monitor periodically scans all certificates stored in Vault, sends alerts when they approach expiration, and can auto-renew them.

## Configuration

```yaml
monitor:
  check_interval_hours: 24
  warn_days: [60, 30, 14, 7, 3, 1]
  alert_webhook_url: "https://hooks.slack.com/services/xxx"
  alert_webhook_headers:
    X-Custom: "value"
  renew_command: >
    certbot renew --cert-name {domain}
    --key-type {key_type} --elliptic-curve {curve}
    --deploy-hook /opt/deploy-hook.sh
    --config-dir /data/acme-git-webhook/letsencrypt
    --work-dir /tmp/certbot-work
    --logs-dir /tmp/certbot-logs
  renew_timeout: 300
  renew_threshold: 14
```

## Sections

### `check_interval_hours`

Default: `24`. How often the APScheduler background job runs. At each tick, the monitor lists all certificates in Vault, parses their expiry dates, and evaluates thresholds.

### `warn_days`

Default: `[60, 30, 14, 7, 3, 1]`. A list of day thresholds. Each threshold fires **once** per certificate — once a warning is sent for a given domain + threshold pair, it is not sent again. This avoids alert fatigue on every check cycle.

Warnings are logged and optionally posted to the alert webhook with severity classification:

| Days left | Severity |
|-----------|----------|
| ≤ 7 | `CRITICAL` |
| ≤ 30 | `WARNING` |
| ≤ 60 | `INFO` |

### `alert_webhook_url`

Optional. When set, sends a JSON POST to this URL when a certificate crosses a threshold:

```json
{
  "text": "Certificate expiration warning: example.com\nDays left: 7\nSeverity: CRITICAL",
  "domain": "example.com",
  "days_left": 7
}
```

Compatible with Slack incoming webhooks, Mattermost, Teams, or any service accepting JSON payloads. Use `alert_webhook_headers` to add custom headers (e.g. authentication tokens).

### Renewal

#### `renew_command`

Optional shell command template. `{domain}` is replaced with the certificate domain at runtime. The template also supports `{key_type}`, `{key_size}`, `{curve}`, `{sig_hash}` from the [`openssl`](configuration.md#openssl) config section.

#### `renew_threshold`

Default: `14`. Certificates are renewed when `days_left <= renew_threshold`. Renewal is triggered once per domain — the domain is added to an internal `_renewing` set to prevent concurrent renewals.

#### `renew_timeout`

Default: `300`. Maximum seconds the renewal subprocess may run before being killed.

## Scheduler

The monitor uses `APScheduler` with a `BackgroundScheduler`. It runs the first check immediately on startup, then at the configured interval.

## Status endpoint

The cached certificate status is exposed at `GET /certs/status`:

```bash
curl -H "Authorization: Bearer $API_KEY" http://localhost:8000/certs/status
```

```json
{
  "certs": [
    {
      "domain": "example.com",
      "expiry": "2026-09-15T00:00:00+00:00",
      "days_left": 45,
      "stored_at": "2025-06-19T10:00:00+00:00"
    }
  ]
}
```

If monitoring is not configured, returns `{"certs": [], "detail": "Monitoring not configured"}`.

## Manual renewal trigger

```bash
curl -X POST http://localhost:8000/acme/renew \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

Returns 400 if `renew_command` is not configured.
