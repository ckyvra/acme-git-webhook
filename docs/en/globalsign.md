# GlobalSign Atlas integration

GlobalSign provides an ACME-compliant endpoint that requires **External Account Binding (EAB)**. This page describes the one-time registration and ongoing renewal workflow.

## Architecture

```
GlobalSign Atlas (ACME endpoint)
    │
    ├─ EAB registration (one-time)
    │   certbot register --eab-kid <KID> --eab-hmac-key <KEY>
    │
    └─ Ongoing renewal (automatic)
        certbot renew --server https://emea.acme.atlas.globalsign.com/directory
```

## 1. Generate EAB credentials

1. Log in to the [GlobalSign Atlas portal](https://atlas.globalsign.com)
2. Navigate to **API Credentials** → **Request an ACME MAC**
3. Copy the displayed **KID** (Key Identifier) and **HMAC key**

## 2. Register the ACME account (one-time)

Use the provided registration script:

```bash
./scripts/register-acme.sh <eab-kid> <eab-hmac-key> admin@example.com
```

This runs:

```bash
certbot register \
    --server https://emea.acme.atlas.globalsign.com/directory \
    --eab-kid "$EAB_KID" \
    --eab-hmac-key "$EAB_HMAC_KEY" \
    --email "$EMAIL" \
    --agree-tos \
    --config-dir /data/acme-git-webhook/letsencrypt \
    --work-dir /tmp/certbot-work \
    --logs-dir /tmp/certbot-logs \
    -n
```

The account is stored in `/data/acme-git-webhook/letsencrypt/accounts/`. Subsequent renewals do **not** need EAB credentials.

## 3. Issue the first certificate manually

```bash
certbot certonly \
    --manual --preferred-challenges dns-01 \
    --manual-auth-hook 'curl -X POST http://localhost:8000/acme/auth \
        -H "Authorization: Bearer <key>" \
        -H "Content-Type: application/json" \
        -d "{\"domain\": \"$CERTBOT_DOMAIN\", \"validation\": \"$CERTBOT_VALIDATION\"}"' \
    --manual-cleanup-hook 'curl -X POST http://localhost:8000/acme/cleanup \
        -H "Authorization: Bearer <key>" \
        -H "Content-Type: application/json" \
        -d "{\"domain\": \"$CERTBOT_DOMAIN\"}"' \
    --deploy-hook /opt/deploy-hook.sh \
    --server https://emea.acme.atlas.globalsign.com/directory \
    --config-dir /data/acme-git-webhook/letsencrypt \
    -d example.com -d "*.example.com"
```

## 4. Automatic renewal

Once the ACME account is registered, configure the monitor to auto-renew:

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

The `{domain}` placeholder is replaced with the certificate domain when auto-renewal triggers.

## Deploy hook script

The certified `deploy-hook.sh` at `/opt/deploy-hook.sh` calls `POST /acme/deploy` to store the renewed certificate in Vault. It reads `RENEWED_DOMAINS`, `RENEWED_LINEAGE`, and the `ACME_WEBHOOK_API_KEY` / `ACME_WEBHOOK_URL` environment variables.

See `scripts/deploy-hook.sh` for the implementation.
