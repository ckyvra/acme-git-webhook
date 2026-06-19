# Démarrage rapide

Ce guide vous permet de démarrer avec acme-git-webhook en quelques minutes.

## Prérequis

- Docker et Docker Compose
- Un dépôt Git contenant vos fichiers de zone Bind
- Un serveur HashiCorp Vault avec AppRole activé
- Un compte ACME (Let's Encrypt ou GlobalSign Atlas)

## Configuration minimale

Créez un fichier `config.yaml` :

```yaml
auth:
  api_keys:
    - "sk-VOTRE-CLE-API"

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

!!! note "Fichiers de zone"
    Les fichiers de zone doivent être nommés `<zone>.zone` (ex. `example.com.zone`)
    et placés sous le répertoire `zone_path`. Le webhook résout la zone correcte
    en essayant les suffixes de domaine progressivement plus courts.

## Démarrage avec Docker Compose

```yaml
# docker-compose.yml
services:
  acme-webhook:
    image: ghcr.io/ckyvra/acme-git-webhook:latest
    ports:
      - "8000:8000"
    volumes:
      - ./config.yaml:/app/config.yaml:ro
      - ./deploy_key:/run/secrets/deploy_key:ro
      - ./vault_secret_id:/run/secrets/vault_secret_id:ro
    environment:
      - CONFIG_PATH=/app/config.yaml
```

Lancez le service :

```bash
docker compose up -d
```

## Première émission de certificat

Créez un script hook `acme-hook.sh` :

```bash
#!/bin/bash
HOOK_URL="https://webhook.example.com:8000"
API_KEY="sk-VOTRE-CLE-API"

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

Rendez-le exécutable et lancez certbot :

```bash
chmod +x acme-hook.sh
certbot certonly --manual --preferred-challenges dns-01 \
  --manual-auth-hook "./acme-hook.sh auth" \
  --manual-cleanup-hook "./acme-hook.sh cleanup" \
  --deploy-hook "./acme-hook.sh deploy" \
  -d example.com -d "*.example.com"
```

## Vérification

Listez les certificats stockés :

```bash
curl -s http://localhost:8000/health
# {"status":"ok"}

curl -s http://localhost:8000/certs/status \
  -H "Authorization: Bearer sk-VOTRE-CLE-API"
```

## Prochaines étapes

- Ajoutez des [cibles de déploiement](targets/f5.md) pour F5, Ivanti ou Exchange
- Configurez la [surveillance](monitoring.md) des certificats
- Passez à l'[autorité GlobalSign](globalsign.md) avec EAB
