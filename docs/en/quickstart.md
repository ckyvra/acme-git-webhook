# Quick start

## 1. Create `config.yaml`

```yaml
auth:
  api_keys:
    - "sk-XXXXXXXXXXXX"

webhook:
  bind: "0.0.0.0:8000"

repo:
  url: "git@github.com:org/dns-zones.git"
  branch: "main"
  zone_path: "zones"
  zone_file_suffix: ".zone"
```

This is the minimum viable configuration. Zone files must be named `<zone>.zone` (e.g. `example.com.zone`) and placed under the `zone_path` subdirectory in the Git repository.

## 2. Start the webhook

```bash
docker compose up --build
```

Mount your SSH deploy key at `/run/secrets/deploy_key` (or set `webhook.ssh_key` in the config).

## 3. First issuance with certbot

Create a hook script `acme-hook.sh`:

```bash
#!/bin/bash
HOOK_URL="https://webhook:8000"
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

Run certbot:

```bash
chmod +x acme-hook.sh
certbot certonly --manual --preferred-challenges dns-01 \
  --manual-auth-hook "./acme-hook.sh auth" \
  --manual-cleanup-hook "./acme-hook.sh cleanup" \
  --deploy-hook "./acme-hook.sh deploy" \
  -d example.com -d "*.example.com"
```

## 4. Deploy the certificate (optional)

```bash
# Deploy to all configured targets
curl -X POST https://webhook:8000/deploy/example.com \
  -H "Authorization: Bearer $API_KEY"

# Deploy to a single target
curl -X POST https://webhook:8000/deploy/example.com/f5-paris \
  -H "Authorization: Bearer $API_KEY"
```

## What's next?

- Add [Vault](configuration.md#vault) for secure certificate storage
- Configure [deploy targets](configuration.md#deploy-targets) to push certificates to F5, Ivanti, or Exchange
- Enable the [monitor](monitoring.md) for expiration alerts and auto-renewal
- Integrate with [GlobalSign Atlas](globalsign.md) as the CA
