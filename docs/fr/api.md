# Référence API

Tous les endpoints (sauf `/health`) nécessitent une authentification
par token Bearer. Incluez l'en-tête `Authorization: Bearer <api_key>`.

## Endpoints

| Endpoint | Méthode | Auth | Body | Description |
|----------|---------|------|------|-------------|
| `/health` | `GET` | Non | — | Healthcheck du service |
| `/acme/auth` | `POST` | Bearer | `{ "domain", "validation" }` | Ajoute un enregistrement TXT + propagation auto optionnelle |
| `/acme/wait-for-propagation` | `POST` | Bearer | `{ "domain", "validation", "nameservers"?, "timeout"?, "poll_interval"? }` | Attend la propagation DNS |
| `/acme/cleanup` | `POST` | Bearer | `{ "domain" }` | Supprime l'enregistrement TXT |
| `/acme/deploy` | `POST` | Bearer | `{ "domain", "cert_pem", "chain_pem"?, "fullchain_pem", "privkey_pem" }` | Stocke le certificat dans Vault uniquement |
| `/acme/renew` | `POST` | Bearer | `{ "domain" }` | Déclenche le renouvellement certbot pour un domaine |
| `/targets` | `GET` | Bearer | — | Liste les cibles de déploiement configurées |
| `/deploy/{domain}` | `POST` | Bearer | — | Déploie le certificat vers toutes les cibles |
| `/deploy/{domain}/{target}` | `POST` | Bearer | — | Déploie le certificat vers une cible spécifique |
| `/certs/status` | `GET` | Bearer | — | Liste les certificats avec jours restants |

---

## Détail des endpoints

### `GET /health`

Vérification que le service est opérationnel.

```bash
curl -s http://localhost:8000/health
```

Réponse :

```json
{"status": "ok"}
```

---

### `POST /acme/auth`

Ajoute un enregistrement TXT `_acme-challenge.<domain>` dans le fichier
de zone, commit et push vers Git. Si `wait_for_propagation` est activé
dans la configuration, l'endpoint attend la propagation DNS avant de
répondre.

```bash
curl -s -X POST http://localhost:8000/acme/auth \
  -H "Authorization: Bearer sk-XXXXXXXXXXXX" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "validation": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  }'
```

Réponse :

```json
{
  "status": "ok",
  "domain": "example.com",
  "record": "_acme-challenge.example.com",
  "propagation": {
    "waited": true,
    "propagated": true,
    "elapsed_seconds": 3.2
  }
}
```

---

### `POST /acme/wait-for-propagation`

Attend que l'enregistrement TXT soit visible sur les serveurs DNS
configurés. Les champs `nameservers`, `timeout` et `poll_interval`
optionnels surchargent la configuration.

```bash
curl -s -X POST http://localhost:8000/acme/wait-for-propagation \
  -H "Authorization: Bearer sk-XXXXXXXXXXXX" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "validation": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "nameservers": ["8.8.8.8"],
    "timeout": 60,
    "poll_interval": 5
  }'
```

---

### `POST /acme/cleanup`

Supprime l'enregistrement TXT `_acme-challenge.<domain>` du fichier
de zone, commit et push vers Git.

```bash
curl -s -X POST http://localhost:8000/acme/cleanup \
  -H "Authorization: Bearer sk-XXXXXXXXXXXX" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

---

### `POST /acme/deploy`

Stocke le certificat émis dans HashiCorp Vault à l'emplacement
`secret/certs/<domain>/`. Le déploiement vers les cibles se fait
séparément via `POST /deploy/{domain}`.

```bash
curl -s -X POST http://localhost:8000/acme/deploy \
  -H "Authorization: Bearer sk-XXXXXXXXXXXX" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
    "chain_pem": "-----BEGIN CERTIFICATE-----\n...",
    "fullchain_pem": "-----BEGIN CERTIFICATE-----\n...",
    "privkey_pem": "-----BEGIN PRIVATE KEY-----\n..."
  }'
```

---

### `POST /acme/renew`

Déclenche le renouvellement certbot pour un domaine. Utilise la
commande configurée dans `monitor.renew_command`.

```bash
curl -s -X POST http://localhost:8000/acme/renew \
  -H "Authorization: Bearer sk-XXXXXXXXXXXX" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

---

### `GET /targets`

Liste les cibles de déploiement configurées :

```bash
curl -s http://localhost:8000/targets \
  -H "Authorization: Bearer sk-XXXXXXXXXXXX"
```

```json
{
  "targets": [
    {"name": "f5-paris", "provider": "f5", "addr": "https://bigip.example.com"},
    {"name": "ivanti-vpn", "provider": "ivanti", "addr": "https://ivanti.example.com"}
  ]
}
```

---

### `POST /deploy/{domain}`

Déploie le certificat du domaine vers toutes les cibles configurées.

```bash
curl -s -X POST http://localhost:8000/deploy/example.com \
  -H "Authorization: Bearer sk-XXXXXXXXXXXX"
```

```json
{
  "status": "ok",
  "domain": "example.com",
  "results": [
    {"target": "f5-paris", "status": "success"},
    {"target": "ivanti-vpn", "status": "success"}
  ]
}
```

Le routage peut être limité à certaines cibles via l'API :

```bash
curl -s -X PATCH http://localhost:8000/certs/example.com/targets \
  -H "Authorization: Bearer sk-XXXXXXXXXXXX" \
  -H "Content-Type: application/json" \
  -d '{"targets": ["f5-paris", "ivanti-vpn"]}'
```

### `POST /deploy/{domain}/{target}`

Déploie le certificat vers une cible spécifique uniquement.

```bash
curl -s -X POST http://localhost:8000/deploy/example.com/f5-paris \
  -H "Authorization: Bearer sk-XXXXXXXXXXXX"
```

---

### `GET /certs/status`

Liste tous les certificats stockés dans Vault avec leur statut
d'expiration.

```bash
curl -s http://localhost:8000/certs/status \
  -H "Authorization: Bearer sk-XXXXXXXXXXXX"
```

```json
{
  "certificates": [
    {
      "domain": "example.com",
      "expiry_date": "2026-09-15T00:00:00Z",
      "days_left": 88,
      "status": "valid"
    },
    {
      "domain": "*.example.com",
      "expiry_date": "2026-09-15T00:00:00Z",
      "days_left": 88,
      "status": "valid"
    }
  ]
}
```

---

## Codes d'erreur

| Code | Signification |
|------|---------------|
| `401` | Clé API manquante ou invalide |
| `404` | Domaine, zone ou cible introuvable |
| `409` | Conflit Git (push rejeté) |
| `422` | Données de requête invalides |
| `500` | Erreur interne (Vault, Git, déploiement) |
