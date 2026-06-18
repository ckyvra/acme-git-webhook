# acme-git-webhook

[![ci](https://github.com/ckyvra/acme-git-webhook/actions/workflows/ci.yml/badge.svg)](https://github.com/ckyvra/acme-git-webhook/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/ckyvra/acme-git-webhook/branch/main/graph/badge.svg)](https://codecov.io/gh/ckyvra/acme-git-webhook)
[![version](https://img.shields.io/github/v/tag/ckyvra/acme-git-webhook?label=version)](https://github.com/ckyvra/acme-git-webhook/tags)
[![ghcr](https://img.shields.io/badge/GHCR-latest-blue?logo=docker)](https://github.com/ckyvra/acme-git-webhook/pkgs/container/acme-git-webhook)

FastAPI webhook that provisions ACME DNS-01 challenges by adding/removing
TXT records in Bind zone files stored in a Git repository, optionally
deploys certificates to F5 Big-IP and monitors certificate expiration.

## How it works

```
ACME client (certbot/acme.sh)
        │
        │  POST /acme/auth { domain, validation }
        │  POST /acme/cleanup { domain }
        │  POST /acme/deploy { domain, cert_pem, ... }
        ▼
acme-git-webhook
        │
        │  1. git pull
        │  2. dnspython: update zone file
        │  3. git commit + push
        │  4. DNS propagation check (optional, auto)
        │  5. Vault: store certificate
        │  6. F5 Big-IP: upload cert + update SSL profile (optional)
        │  7. Monitor: check expiration (optional)
        ├──────────────────────┬───────────────────────┬───────────────────┐
        ▼                      ▼                       ▼                    ▼
GitHub repo           HashiCorp Vault          F5 Big-IP            Logs / Webhook
(Bind zones)          (KV store)               (iControl REST)      (alert on expiry)
        │                      │                       │
        │  CI/CD               │  Services retrieve     │  SSL profile updated
        ▼                      ▼                       ▼
Authoritative DNS      secret/certs/          /Common/example.com
```

The ACME client calls the webhook three times per certificate:
1. **auth** — injects `_acme-challenge.<domain>. IN TXT "<validation>"` into the zone file and pushes to Git
2. **cleanup** — removes the TXT record after validation
3. **deploy** — stores the issued certificate in HashiCorp Vault, then uploads it to F5 Big-IP and updates matching Client SSL profiles (if configured)

## Configuration

Edit `config.yaml`:

```yaml
auth:
  api_keys:
    - "sk-XXXXXXXXXXXX"

repo:
  url: "git@github.com:org/dns-zones.git"
  branch: "main"
  zone_path: "zones"
  zone_file_suffix: ".zone"

vault:
  addr: "https://vault.example.com:8200"
  role_id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  secret_id_path: "/run/secrets/vault_secret_id"
  kv_mount: "secret"
  certs_path: "certs"
  verify: true
  skip: false
```

Zone files are named `<zone_name>.zone` (e.g. `example.com.zone`) and
located under `zone_path`. The webhook resolves the correct zone by
trying progressively shorter domain suffixes.

Vault AppRole is used for authentication. The `secret_id` is read from
a file at runtime (never stored in the config file). Mount the file
as a Docker secret at the path specified by `secret_id_path`.

### DNS propagation (optional)

```yaml
dns:
  nameservers:
    - "8.8.8.8"
    - "1.1.1.1"
  timeout: 120
  poll_interval: 5
  wait_for_propagation: true
```

When `wait_for_propagation` is `true`, the `/acme/auth` endpoint
automatically polls the configured nameservers after pushing the
zone change and waits until the TXT record is visible (or the
`timeout` is reached). The propagation result is included in the
auth response, removing the need for a separate call to
`/acme/wait-for-propagation`.

The `/acme/wait-for-propagation` endpoint also uses these defaults
when request fields are omitted.

### F5 Big-IP (optional)

```yaml
f5:
  hosts:
    - addr: "https://bigip.example.com"
      username: "admin"
      password_path: "/run/secrets/f5_password"
      verify: true
```

When configured, the `/acme/deploy` endpoint uploads the fullchain and
private key to each F5 host via iControl REST, then auto-detects Client
SSL profiles whose `cert` field contains the domain name and updates them
to use the new certificate.

### Certificate expiration monitoring (optional)

```yaml
monitor:
  check_interval_hours: 24
  warn_days: [60, 30, 14, 7, 3, 1]
  alert_webhook_url: "https://hooks.slack.com/services/xxx"
```

The monitor reads all certificates from Vault on a schedule and logs a
warning when a certificate is within the configured `warn_days` thresholds.
If `alert_webhook_url` is set, it sends a JSON POST alert. The cached
status is also exposed via `GET /certs/status`.

## API

| Endpoint                       | Method | Auth   | Body                                                                                               | Description                     |
|--------------------------------|--------|--------|----------------------------------------------------------------------------------------------------|---------------------------------|
| `/health`                      | GET    | No     | —                                                                                                  | Healthcheck                     |
| `/acme/auth`                   | POST   | Bearer | `{ "domain", "validation" }`                                                                      | Add TXT record + optional auto propagation |
| `/acme/wait-for-propagation`   | POST   | Bearer | `{ "domain", "validation", "nameservers"?, "timeout"?, "poll_interval"? }`                         | Wait for DNS propagation (uses config defaults) |
| `/acme/cleanup`                | POST   | Bearer | `{ "domain" }`                                                                                     | Remove TXT record               |
| `/acme/deploy`                 | POST   | Bearer | `{ "domain", "cert_pem", "chain_pem"?, "fullchain_pem", "privkey_pem" }`                           | Store certificate in Vault + deploy to F5 |
| `/certs/status`                | GET    | Bearer | —                                                                                                  | List certificates and days left |

## Certbot usage

Create a hook script `acme-hook.sh`:

When `wait_for_propagation: true` in the config, only one call per
phase is needed — the auth endpoint handles propagation internally:

```bash
#!/bin/bash
HOOK_URL="https://webhook.example.com:8000"
API_KEY="sk-XXXXXXXXXXXX"

if [ "$1" = "auth" ]; then
  curl -s -X POST "$HOOK_URL/acme/auth" \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"domain\": \"$CERTBOT_DOMAIN\", \"validation\": \"$CERTBOT_VALIDATION\"}"

elif [ "$1" = "cleanup" ]; then
  curl -s -X POST "$HOOK_URL/acme/cleanup" \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"domain\": \"$CERTBOT_DOMAIN\"}"

elif [ "$1" = "deploy" ]; then
  FIRST_DOMAIN=$(echo "$RENEWED_DOMAINS" | cut -d' ' -f1)
  curl -s -X POST "$HOOK_URL/acme/deploy" \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{
      \"domain\": \"$FIRST_DOMAIN\",
      \"cert_pem\": $(jq -Rs . < \"$RENEWED_LINEAGE/cert.pem\"),
      \"chain_pem\": $(jq -Rs . < \"$RENEWED_LINEAGE/chain.pem\"),
      \"fullchain_pem\": $(jq -Rs . < \"$RENEWED_LINEAGE/fullchain.pem\"),
      \"privkey_pem\": $(jq -Rs . < \"$RENEWED_LINEAGE/privkey.pem\")
    }"
fi
```

```bash
chmod +x acme-hook.sh
certbot certonly --manual --preferred-challenges dns-01 \
  --manual-auth-hook "./acme-hook.sh auth" \
  --manual-cleanup-hook "./acme-hook.sh cleanup" \
  --deploy-hook "./acme-hook.sh deploy" \
  -d example.com -d "*.example.com"
```

## Deployment

```bash
docker compose up --build
```

Mount your SSH deploy key at `/run/secrets/deploy_key` and set the
`CONFIG_PATH` environment variable if needed.

## GlobalSign Atlas (alternative CA)

GlobalSign requires **External Account Binding (EAB)** for its ACME service.
Register once, then renew automatically.

### 1. Generate EAB credentials

1. Log in to [Atlas portal](https://atlas.globalsign.com)
2. Go to **API Credentials** → **Request an ACME MAC**
3. Copy the displayed **KID** and **HMAC key**

### 2. Register the ACME account (one-time)

```bash
./scripts/register-acme.sh <eab-kid> <eab-hmac-key> admin@example.com
```

This runs `certbot register` with the GlobalSign endpoint and stores
the account in `/data/acme-git-webhook/letsencrypt/accounts/`.

### 3. Issue the first certificate

```bash
certbot certonly \
  --manual --preferred-challenges dns-01 \
  --manual-auth-hook 'curl -X POST http://localhost:8000/acme/auth -H "Authorization: Bearer <key>" -H "Content-Type: application/json" -d "{\"domain\": \"$CERTBOT_DOMAIN\", \"validation\": \"$CERTBOT_VALIDATION\"}"' \
  --manual-cleanup-hook 'curl -X POST http://localhost:8000/acme/cleanup -H "Authorization: Bearer <key>" -H "Content-Type: application/json" -d "{\"domain\": \"$CERTBOT_DOMAIN\"}"' \
  --deploy-hook /opt/deploy-hook.sh \
  --server https://emea.acme.atlas.globalsign.com/directory \
  --config-dir /data/acme-git-webhook/letsencrypt \
  -d example.com -d "*.example.com"
```

### 4. Automatic renewal

Once registered, certbot renews without EAB. Enable in `config.yaml`:

```yaml
monitor:
  renew_command: >
    certbot renew --cert-name {domain}
    --server https://emea.acme.atlas.globalsign.com/directory
    --deploy-hook /opt/deploy-hook.sh
    --config-dir /data/acme-git-webhook/letsencrypt
    --work-dir /tmp/certbot-work
    --logs-dir /tmp/certbot-logs
  renew_threshold: 14
```

## Development

```bash
make test        # install venv + run pytest
make lint        # syntax check
make check       # lint + test
make clean       # remove venv and caches
```

## Tests

```bash
pip install -r dev-requirements.txt
pytest -v
```

## Helm chart

A Helm chart is available in `helm/`. All secrets (API key, SSH deploy
key, Vault AppRole secret, F5 password, GlobalSign EAB) are sourced
from HashiCorp Vault via the **External Secrets Operator**. Populate a
Vault secret at the path configured in `values.yaml`:

```hcl
path "secret/data/acme-webhook" {
  capabilities = ["read"]
}
```

The secret must contain these properties: `api_key`, `deploy_key`,
`vault_secret_id`, `f5_password`, `acme_eab_kid`, `acme_eab_hmac_key`,
`acme_email`.

Quick start:

```bash
# 1. Edit non-sensitive configuration
vim helm/values.yaml

# 2. Install the chart — the ExternalSecret pulls secrets from Vault
helm install acme-webhook ./helm

# 3. The post-install Job registers the GlobalSign ACME account
kubectl wait --for=condition=complete job/acme-webhook-acme-git-webhook-certbot-init --timeout=60s

# 4. Verify
kubectl get pods -l app.kubernetes.io/instance=acme-webhook
```

### values.yaml overview

| Section | Key features |
|---------|-------------|
| `externalSecret.*` | ESO SecretStore reference + Vault path |
| `repo.*` | Git repository URL, branch, zone path |
| `vault.*` | HashiCorp Vault address, AppRole role_id, verify |
| `dns.*` | Nameservers, timeout, auto-propagation on/off |
| `f5.*` | Big-IP hosts (addr, username, verify) |
| `monitor.*` | Check interval, warning thresholds, renew command |
| `acme.*` | Enable/disable the GlobalSign registration Job |
| `ingress.*` | Hostname, ingress class, cert-manager issuer |
| `persistence.*` | PVC size and access mode |

## License

MIT
