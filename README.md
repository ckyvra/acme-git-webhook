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
        ▼
acme-git-webhook
        │
        │  1. git pull
        │  2. dnspython: update zone file
        │  3. git commit + push
        ▼
GitHub repository (Bind zone files)
        │
        │  CI/CD detects push
        ▼
Authoritative DNS servers (rndc reload)
```

The ACME client calls the webhook twice per certificate:
1. **auth** — injects `_acme-challenge.<domain>. IN TXT "<validation>"` into the zone file and pushes to Git
2. **cleanup** — removes the TXT record after validation

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
```

Zone files are named `<zone_name>.zone` (e.g. `example.com.zone`) and
located under `zone_path`. The webhook resolves the correct zone by
trying progressively shorter domain suffixes.

## API

| Endpoint | Method | Auth | Body | Description |
|---|---|---|---|---|
| `/health` | GET | No | — | Healthcheck |
| `/acme/auth` | POST | Bearer | `{ "domain", "validation" }` | Add TXT record |
| `/acme/wait-for-propagation` | POST | Bearer | `{ "domain", "validation", "nameservers"?, "timeout"?, "poll_interval"? }` | Wait for DNS propagation |
| `/acme/cleanup` | POST | Bearer | `{ "domain" }` | Remove TXT record |

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
fi
```

```bash
chmod +x acme-hook.sh
certbot certonly --manual --preferred-challenges dns-01 \
  --manual-auth-hook "./acme-hook.sh auth" \
  --manual-cleanup-hook "./acme-hook.sh cleanup" \
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
