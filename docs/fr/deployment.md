# Déploiement

## Docker Compose

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
    restart: unless-stopped
```

```bash
docker compose up -d
```

### Fichiers secrets requis

| Fichier | Rôle |
|---------|------|
| `deploy_key` | Clé SSH pour l'accès au dépôt Git |
| `vault_secret_id` | Secret ID AppRole Vault |
| `f5_password` | Mot de passe F5 (si cible F5 configurée) |
| `ivanti_api_key` | Clé API Ivanti (si cible Ivanti configurée) |
| `exchange_password` | Mot de passe Exchange (si cible Exchange configurée) |

## Helm (Kubernetes)

Un chart Helm est disponible dans le répertoire `helm/`.

### Prérequis

- Kubernetes 1.22+
- Helm 3+
- External Secrets Operator installé dans le cluster
- Un secret Vault contenant les identifiants sensibles

### Installation

```bash
# 1. Éditer la configuration non sensible
vim helm/values.yaml

# 2. Installer le chart
helm install acme-webhook ./helm

# 3. Attendre l'enregistrement du compte ACME (GlobalSign)
kubectl wait --for=condition=complete job/acme-webhook-acme-git-webhook-certbot-init --timeout=60s

# 4. Vérifier
kubectl get pods -l app.kubernetes.io/instance=acme-webhook
```

### Structure de `values.yaml`

| Section | Rôle |
|---------|------|
| `externalSecret.*` | Référence SecretStore ESO + chemin Vault |
| `repo.*` | URL du dépôt Git, branche, chemin des zones |
| `vault.*` | Adresse Vault, AppRole role_id, verify |
| `dns.*` | Serveurs DNS, timeout, propagation auto |
| `targets.*` | Cibles de déploiement (F5, Ivanti, Exchange…) |
| `monitor.*` | Intervalle, seuils d'alerte, commande de renouvellement |
| `acme.*` | Activation du Job d'enregistrement GlobalSign |
| `ingress.*` | Hostname, classe Ingress, issuer cert-manager |
| `persistence.*` | Taille et mode d'accès du PVC |

### Secrets Vault

Le secret Vault doit contenir les propriétés suivantes :

```hcl
path "secret/data/acme-webhook" {
  capabilities = ["read"]
}
```

| Propriété | Description |
|-----------|-------------|
| `api_key` | Clé API du webhook |
| `deploy_key` | Clé SSH de déploiement Git |
| `vault_secret_id` | Secret ID Vault AppRole |
| `f5_password` | Mot de passe F5 Big-IP |
| `acme_eab_kid` | KID GlobalSign EAB |
| `acme_eab_hmac_key` | Clé HMAC GlobalSign EAB |
| `acme_email` | Email du compte ACME |

### Ingress

Le chart configure automatiquement un Ingress avec cert-manager pour
le chiffrement TLS :

```yaml
ingress:
  enabled: true
  hostname: webhook.example.com
  ingressClassName: nginx
  clusterIssuer: letsencrypt-prod
```

## Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `CONFIG_PATH` | `/app/config.yaml` | Chemin du fichier de configuration |
| `LOG_LEVEL` | Valeur de `webhook.log_level` | Niveau de log |

## Sécurité

- Les secrets sont montés en fichiers, jamais passés en variables
  d'environnement ou dans le fichier YAML.
- Utilisez toujours `secrets.compare_digest()` pour la comparaison
  des tokens (déjà implémenté).
- En production, activez TLS sur le endpoint du webhook (via un
  reverse proxy ou l'Ingress Kubernetes).
