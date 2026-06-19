# API reference

## Endpoint table

All authenticated endpoints expect an `Authorization: Bearer <token>` header. Tokens are validated against `auth.api_keys` using constant-time comparison to prevent timing side-channel attacks.

| Method | Path | Auth | Body | Description |
|--------|------|------|------|-------------|
| `GET` | `/health` | No | — | Healthcheck |
| `POST` | `/acme/auth` | Bearer | `{ "domain", "validation" }` | Add TXT record + optional auto propagation |
| `POST` | `/acme/wait-for-propagation` | Bearer | `{ "domain", "validation", "nameservers"?, "timeout"?, "poll_interval"? }` | Wait for DNS propagation |
| `POST` | `/acme/cleanup` | Bearer | `{ "domain" }` | Remove TXT record |
| `POST` | `/acme/deploy` | Bearer | `{ "domain", "cert_pem", "chain_pem"?, "fullchain_pem", "privkey_pem" }` | Store certificate in Vault |
| `POST` | `/acme/renew` | Bearer | `{ "domain" }` | Trigger certbot renew for a domain |
| `GET` | `/targets` | Bearer | — | List configured deploy targets |
| `POST` | `/deploy/{domain}` | Bearer | `{ "target_names"?, "fullchain_pem"?, "privkey_pem"? }` | Deploy cert to all (or selected) targets |
| `POST` | `/deploy/{domain}/{target}` | Bearer | — | Deploy cert to a specific target |
| `GET` | `/certs/status` | Bearer | — | List certificates and days left |

---

## Examples

### Healthcheck

```bash
curl -s http://localhost:8000/health
```

Response:

```json
{ "status": "ok" }
```

### ACME auth

```bash
curl -s -X POST http://localhost:8000/acme/auth \
  -H "Authorization: Bearer sk-XXXXXXXXXXXX" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "_acme-challenge.example.com",
    "validation": "xxxxxxxxxxxxxxxxxxxxxxxxxxx"
  }'
```

Response (with `wait_for_propagation: true`):

```json
{
  "status": "ok",
  "domain": "_acme-challenge.example.com",
  "zone_file": "example.com.zone",
  "propagation": "propagated",
  "propagation_matched": ["8.8.8.8", "1.1.1.1"],
  "propagation_pending": [],
  "propagation_elapsed": 6
}
```

### ACME cleanup

```bash
curl -s -X POST http://localhost:8000/acme/cleanup \
  -H "Authorization: Bearer sk-XXXXXXXXXXXX" \
  -H "Content-Type: application/json" \
  -d '{"domain": "_acme-challenge.example.com"}'
```

Response:

```json
{
  "status": "ok",
  "domain": "_acme-challenge.example.com",
  "zone_file": "example.com.zone"
}
```

If no TXT record was found:

```json
{
  "status": "skipped",
  "domain": "_acme-challenge.example.com",
  "detail": "No TXT record found to remove"
}
```

### ACME deploy (store in Vault)

```bash
curl -s -X POST http://localhost:8000/acme/deploy \
  -H "Authorization: Bearer sk-XXXXXXXXXXXX" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
    "fullchain_pem": "-----BEGIN CERTIFICATE-----\n...",
    "privkey_pem": "-----BEGIN PRIVATE KEY-----\n..."
  }'
```

Response:

```json
{
  "status": "ok",
  "domain": "example.com",
  "vault_path": "secret/certs/example.com"
}
```

If Vault is not configured:

```json
{
  "status": "skipped",
  "domain": "example.com",
  "detail": "Vault not configured or skip=true"
}
```

### Deploy to targets

```bash
# All targets
curl -s -X POST http://localhost:8000/deploy/example.com \
  -H "Authorization: Bearer sk-XXXXXXXXXXXX"

# Specific target
curl -s -X POST http://localhost:8000/deploy/example.com/f5-paris \
  -H "Authorization: Bearer sk-XXXXXXXXXXXX"
```

### Certificate status

```bash
curl -s http://localhost:8000/certs/status \
  -H "Authorization: Bearer sk-XXXXXXXXXXXX"
```

Response:

```json
{
  "certs": [
    {
      "domain": "example.com",
      "expiry": "2026-06-15T00:00:00+00:00",
      "days_left": 45,
      "stored_at": "2025-06-19T10:00:00+00:00"
    }
  ]
}
```

### Configure deploy routing per domain

Per-domain target routing is stored in Vault metadata via `PATCH`. This is not a dedicated endpoint but is managed through Vault directly or external automation.

```bash
curl -X PATCH http://localhost:8000/certs/example.com/targets \
  -H "Authorization: Bearer sk-XXXXXXXXXXXX" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["f5-paris", "ivanti-vpn"]}'
```

## Rate limiting

All endpoints (including health) are rate-limited to **30 requests per minute** per client IP via `slowapi`. Exceeding the limit returns:

```json
{
  "detail": "Rate limit exceeded, try again later"
}
```

Status code: `429 Too Many Requests`.

## Error responses

| Code | Description |
|------|-------------|
| `401` | Invalid or missing API key |
| `423` | Another ACME operation is in progress (file lock held) |
| `429` | Rate limit exceeded |
| `500` | Configuration not loaded or server error |
| `502` | Vault operation failed |
