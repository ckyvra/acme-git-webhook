# Deployment

## Docker

### Build

```bash
docker build -t ghcr.io/ckyvra/acme-git-webhook:latest .
```

The Dockerfile is based on `python:3.12-slim` and includes `git`, `openssh-client`, and `certbot`.

### Run

```bash
docker run -d \
  --name acme-webhook \
  -p 8000:8000 \
  -v /path/to/config.yaml:/app/config.yaml:ro \
  -v /path/to/deploy_key:/run/secrets/deploy_key:ro \
  -v webhook_data:/data/acme-git-webhook \
  -e CONFIG_PATH=/app/config.yaml \
  ghcr.io/ckyvra/acme-git-webhook:latest
```

## Docker Compose

```yaml
services:
  webhook:
    build: .
    restart: unless-stopped
    ports:
      - "8000:8000"
    volumes:
      - /path/to/deploy_key:/run/secrets/deploy_key:ro
      - /path/to/vault_secret_id:/run/secrets/vault_secret_id:ro
      - webhook_data:/data/acme-git-webhook
    environment:
      - CONFIG_PATH=/app/config.yaml
      - ACME_WEBHOOK_API_KEY=your-api-key-here
      - ACME_WEBHOOK_URL=http://localhost:8000

volumes:
  webhook_data:
```

Start with:

```bash
docker compose up --build
```

## Helm chart

A Helm chart is available in the `helm/` directory for Kubernetes deployment.

### Prerequisites

- Kubernetes cluster with the **External Secrets Operator** installed
- A Vault secret at the configured path containing: `api_key`, `deploy_key`, `vault_secret_id`, `f5_password`, `acme_eab_kid`, `acme_eab_hmac_key`, `acme_email`

### `values.yaml` reference

| Section | Key features |
|---------|-------------|
| `replicaCount` | Number of pod replicas (default: `1`) |
| `image.*` | Container image repository, tag, pull policy |
| `externalSecret.*` | ESO SecretStore reference and Vault path for secrets |
| `externalSecret.secretStore` | Name and kind (`ClusterSecretStore` or `SecretStore`) |
| `externalSecret.vault.path` | Vault path for the external secret (default: `secret/data/acme-webhook`) |
| `repo.*` | Git URL, branch, zone path, zone file suffix |
| `vault.*` | Vault address, AppRole `roleId`, KV mount, certs path, TLS verify |
| `dns.*` | Nameservers, timeout, poll interval, auto-propagation toggle |
| `monitor.*` | Check interval, warning thresholds, alert webhook, renew command, threshold |
| `acme.enabled` | Enable/disable the GlobalSign ACME registration post-install Job |
| `ingress.*` | Ingress hostname, class name, TLS issuer |
| `persistence.*` | PVC size (default: `1Gi`) and access mode |
| `service.*` | Service port and type (default: `ClusterIP`) |
| `resources.*` | Pod CPU/memory requests and limits |

### Quick start

```bash
# 1. Edit non-sensitive configuration
vim helm/values.yaml

# 2. Install the chart — the ExternalSecret pulls secrets from Vault
helm install acme-webhook ./helm

# 3. Wait for the GlobalSign registration Job (if enabled)
kubectl wait --for=condition=complete \
  job/acme-webhook-acme-git-webhook-certbot-init --timeout=60s

# 4. Verify
kubectl get pods -l app.kubernetes.io/instance=acme-webhook
```

### Required Vault secret

The Vault secret at the path specified in `externalSecret.vault.path` must contain:

| Key | Description |
|-----|-------------|
| `api_key` | Bearer token for API authentication |
| `deploy_key` | SSH private key for Git repository access |
| `vault_secret_id` | AppRole SecretID for HashiCorp Vault |
| `f5_password` | Password for F5 Big-IP authentication |
| `acme_eab_kid` | GlobalSign ACME EAB Key ID |
| `acme_eab_hmac_key` | GlobalSign ACME EAB HMAC key |
| `acme_email` | Email for ACME account registration |

Vault policy:

```hcl
path "secret/data/acme-webhook" {
  capabilities = ["read"]
}
```

### Environment variables

| Variable | Description |
|----------|-------------|
| `CONFIG_PATH` | Path to the YAML configuration file (default: `config.yaml`) |
| `ACME_WEBHOOK_API_KEY` | Additional API key appended to `auth.api_keys` at startup |
| `ACME_WEBHOOK_URL` | Base URL used by the deploy hook script |
