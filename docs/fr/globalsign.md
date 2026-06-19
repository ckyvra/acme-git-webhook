# GlobalSign Atlas

GlobalSign propose un service ACME compatible avec **External Account
Binding (EAB)**. L'enregistrement du compte se fait une seule fois,
les renouvellements sont automatiques sans EAB.

## 1. Générer les identifiants EAB

1. Connectez-vous au [portail Atlas](https://atlas.globalsign.com).
2. Accédez à **API Credentials** → **Request an ACME MAC**.
3. Copiez le **KID** et la **clé HMAC** affichés.

## 2. Enregistrer le compte ACME (une seule fois)

Utilisez le script fourni :

```bash
./scripts/register-acme.sh <eab-kid> <eab-hmac-key> admin@example.com
```

Cette commande exécute `certbot register` avec l'endpoint GlobalSign
et stocke le compte dans `/data/acme-git-webhook/letsencrypt/accounts/`.

### Contenu du script

```bash
#!/bin/bash
# scripts/register-acme.sh
EAB_KID=$1
EAB_HMAC=$2
EMAIL=$3

certbot register \
  --server https://emea.acme.atlas.globalsign.com/directory \
  --eab-kid "$EAB_KID" \
  --eab-hmac-key "$EAB_HMAC" \
  --email "$EMAIL" \
  --config-dir /data/acme-git-webhook/letsencrypt \
  --agree-tos \
  --no-eff-email
```

## 3. Émettre le premier certificat

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

## 4. Renouvellement automatique

Une fois le compte enregistré, certbot peut renouveler sans EAB.
Configurez le renouvellement automatique dans `config.yaml` :

```yaml
monitor:
  check_interval_hours: 24
  renew_command: >
    certbot renew --cert-name {domain}
    --server https://emea.acme.atlas.globalsign.com/directory
    --deploy-hook /opt/deploy-hook.sh
    --config-dir /data/acme-git-webhook/letsencrypt
    --work-dir /tmp/certbot-work
    --logs-dir /tmp/certbot-logs
  renew_threshold: 14
```

## Helm et secrets EAB

En déploiement Helm, les secrets EAB sont stockés dans Vault et
récupérés via External Secrets Operator :

```hcl
# Politique Vault
path "secret/data/acme-webhook" {
  capabilities = ["read"]
}
```

Le secret Vault doit contenir :

| Propriété | Description |
|-----------|-------------|
| `acme_eab_kid` | KID EAB GlobalSign |
| `acme_eab_hmac_key` | Clé HMAC EAB GlobalSign |
| `acme_email` | Email du compte ACME |

Un Job post-installation enregistre automatiquement le compte ACME
lors du premier déploiement Helm :

```bash
helm install acme-webhook ./helm

# Attendre l'enregistrement du compte ACME
kubectl wait --for=condition=complete job/acme-webhook-acme-git-webhook-certbot-init --timeout=60s
```

## Alterner entre Let's Encrypt et GlobalSign

Pour utiliser Let's Encrypt, omettez simplement `--server` dans les
commandes certbot (Let's Encrypt est l'autorité par défaut). Pour
GlobalSign, ajoutez l'URL du directory GlobalSign.
