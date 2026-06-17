# acme-git-webhook

[![ci](https://github.com/ckyvra/acme-git-webhook/actions/workflows/ci.yml/badge.svg)](https://github.com/ckyvra/acme-git-webhook/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/ckyvra/acme-git-webhook/branch/main/graph/badge.svg)](https://codecov.io/gh/ckyvra/acme-git-webhook)
[![version](https://img.shields.io/github/v/tag/ckyvra/acme-git-webhook?label=version)](https://github.com/ckyvra/acme-git-webhook/tags)
[![ghcr](https://img.shields.io/badge/GHCR-latest-blue?logo=docker)](https://github.com/ckyvra/acme-git-webhook/pkgs/container/acme-git-webhook)

FastAPI webhook that provisions ACME DNS-01 challenges by adding/removing
TXT records in Bind zone files stored in a Git repository.

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
        │  1. git pull / Vault store
        │  2. dnspython: update zone file
        │  3. git commit + push
        ▼
GitHub repository (Bind zone files)     HashiCorp Vault (KV store)
        │                                         │
        │  CI/CD detects push                     │  Services retrieve
        ▼                                         ▼
Authoritative DNS servers (rndc reload)    secret/certs/example.com/
```

The ACME client calls the webhook three times per certificate:
1. **auth** — injects `_acme-challenge.<domain>. IN TXT "<validation>"` into the zone file and pushes to Git
2. **cleanup** — removes the TXT record after validation
3. **deploy** — stores the issued certificate (cert + key + chain) in HashiCorp Vault for secure distribution

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

## API

| Endpoint                       | Method | Auth   | Body                                                                                               | Description                     |
|--------------------------------|--------|--------|----------------------------------------------------------------------------------------------------|---------------------------------|
| `/health`                      | GET    | No     | —                                                                                                  | Healthcheck                     |
| `/acme/auth`                   | POST   | Bearer | `{ "domain", "validation" }`                                                                      | Add TXT record                  |
| `/acme/wait-for-propagation`   | POST   | Bearer | `{ "domain", "validation", "nameservers"?, "timeout"?, "poll_interval"? }`                         | Wait for DNS propagation        |
| `/acme/cleanup`                | POST   | Bearer | `{ "domain" }`                                                                                     | Remove TXT record               |
| `/acme/deploy`                 | POST   | Bearer | `{ "domain", "cert_pem", "chain_pem"?, "fullchain_pem", "privkey_pem" }`                           | Store certificate in Vault      |

## Certbot usage

Create a hook script `acme-hook.sh`:

```bash
#!/bin/bash
HOOK_URL="https://webhook.example.com:8000"
API_KEY="sk-XXXXXXXXXXXX"

if [ "$1" = "auth" ]; then
  curl -s -X POST "$HOOK_URL/acme/auth" \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"domain\": \"$CERTBOT_DOMAIN\", \"validation\": \"$CERTBOT_VALIDATION\"}"

  curl -s -X POST "$HOOK_URL/acme/wait-for-propagation" \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"domain\": \"$CERTBOT_DOMAIN\", \"validation\": \"$CERTBOT_VALIDATION\", \"timeout\": 120, \"poll_interval\": 5}"

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

## License

MIT
