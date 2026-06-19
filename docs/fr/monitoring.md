# Surveillance des certificats

Le module de surveillance vérifie périodiquement l'expiration des
certificats stockés dans Vault, envoie des alertes et peut déclencher
le renouvellement automatique.

## Configuration

```yaml
monitor:
  check_interval_hours: 24
  warn_days: [60, 30, 14, 7, 3, 1]
  alert_webhook_url: "https://hooks.slack.com/services/xxx"
  renew_command: >
    certbot renew --cert-name {domain}
    --server https://emea.acme.atlas.globalsign.com/directory
    --deploy-hook /opt/deploy-hook.sh
    --config-dir /data/acme-git-webhook/letsencrypt
    --work-dir /tmp/certbot-work
    --logs-dir /tmp/certbot-logs
  renew_threshold: 14
```

| Champ | Type | Défaut | Description |
|-------|------|--------|-------------|
| `check_interval_hours` | `int` | `24` | Intervalle entre les vérifications (heures) |
| `warn_days` | `list[int]` | `[60, 30, 14, 7, 3, 1]` | Seuils d'alerte (jours avant expiration) |
| `alert_webhook_url` | `Optional[str]` | `None` | URL webhook pour les alertes |
| `renew_command` | `Optional[str]` | `None` | Commande de renouvellement (le marqueur `{domain}` est remplacé) |
| `renew_threshold` | `int` | `14` | Seuil de renouvellement automatique (jours) |

## Fonctionnement

### Vérification périodique

Un processus background lit tous les certificats depuis Vault à
intervalles réguliers (`check_interval_hours`). Pour chaque certificat :

1. La date d'expiration est extraite du certificat X.509.
2. Le nombre de jours restants est calculé.
3. Si ce nombre correspond à l'un des seuils `warn_days`, une alerte
   est émise.
4. Si `renew_command` est configuré et que le seuil `renew_threshold`
   est atteint, la commande de renouvellement est exécutée.

### Alertes

Les alertes sont envoyées au format JSON à l'URL configurée dans
`alert_webhook_url` :

```json
{
  "domain": "example.com",
  "days_left": 14,
  "expiry_date": "2026-07-03T00:00:00Z",
  "message": "Le certificat example.com expire dans 14 jours"
}
```

!!! tip "Intégration Slack"
    Utilisez une URL Slack Incoming Webhook pour recevoir les alertes
    directement dans un canal Slack.

### API de statut

Le statut mis en cache est exposé via l'API REST :

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

Les statuts possibles :

| Statut | Description |
|--------|-------------|
| `valid` | Certificat valide, aucun seuil d'alerte atteint |
| `warning` | Certificat dans une fenêtre d'alerte (`warn_days`) |
| `expiring_soon` | Seuil de renouvellement atteint, renouvellement en cours |
| `renewing` | Renouvellement en cours d'exécution |
| `expired` | Certificat expiré |

### Renouvellement automatique

Lorsque `renew_command` est configuré, le moniteur exécute la commande
pour tout certificat dont le nombre de jours restants est inférieur ou
égal à `renew_threshold`. La commande peut inclure le marqueur
`{domain}` qui est remplacé par le nom de domaine du certificat.

Exemple pour Let's Encrypt :

```yaml
monitor:
  renew_command: "certbot renew --cert-name {domain}"
  renew_threshold: 14
```

Exemple pour GlobalSign Atlas :

```yaml
monitor:
  renew_command: >
    certbot renew --cert-name {domain}
    --server https://emea.acme.atlas.globalsign.com/directory
    --deploy-hook /opt/deploy-hook.sh
    --config-dir /data/acme-git-webhook/letsencrypt
  renew_threshold: 14
```

Le renouvellement peut aussi être déclenché manuellement via l'API :

```bash
curl -s -X POST http://localhost:8000/acme/renew \
  -H "Authorization: Bearer sk-XXXXXXXXXXXX" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

## Logs

Les événements de surveillance sont enregistrés dans les logs de
l'application :

```
[INFO] Certificate check completed: 12 certificates, 0 warnings, 0 renewals
[WARN] Certificate example.com expires in 14 days
[INFO] Auto-renewal triggered for example.com
[INFO] Renewal command completed for example.com: exit code 0
```
