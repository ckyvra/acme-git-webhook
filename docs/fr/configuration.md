# Configuration

Toute la configuration se fait via un fichier YAML. Par défaut, le chemin
est `/app/config.yaml` mais il peut être surchargé avec la variable
d'environnement `CONFIG_PATH`.

## Structure générale

```yaml
auth:        # Authentification API
webhook:     # Configuration du serveur HTTP
repo:        # Dépôt Git des zones DNS
vault:       # HashiCorp Vault
dns:         # Propagation DNS (optionnel)
openssl:     # Options OpenSSL (optionnel)
monitor:     # Surveillance des certificats (optionnel)
targets:     # Cibles de déploiement (optionnel)
```

---

## `auth`

Contrôle l'authentification par clé API.

```yaml
auth:
  api_keys:
    - "sk-XXXXXXXXXXXX"
    - "sk-YYYYYYYYYYYY"
```

| Champ | Type | Défaut | Description |
|-------|------|--------|-------------|
| `api_keys` | `list[str]` | **requis** | Liste des clés API autorisées (en-tête `Authorization: Bearer <key>`) |

!!! warning "Sécurité"
    Les clés API doivent être des chaînes longues et aléatoires.
    Ne jamais commiter de clés réelles dans le dépôt.

---

## `webhook`

Configuration du serveur HTTP FastAPI.

```yaml
webhook:
  host: "0.0.0.0"
  port: 8000
  log_level: "info"
```

| Champ | Type | Défaut | Description |
|-------|------|--------|-------------|
| `host` | `str` | `"0.0.0.0"` | Adresse d'écoute |
| `port` | `int` | `8000` | Port d'écoute |
| `log_level` | `str` | `"info"` | Niveau de log (`debug`, `info`, `warning`, `error`) |

---

## `repo`

Configuration du dépôt Git contenant les fichiers de zone Bind.

```yaml
repo:
  url: "git@github.com:org/dns-zones.git"
  branch: "main"
  zone_path: "zones"
  zone_file_suffix: ".zone"
  deploy_key_path: "/run/secrets/deploy_key"
  known_hosts_path: "/run/secrets/known_hosts"
  git_user_name: "acme-git-webhook"
  git_user_email: "webhook@example.com"
```

| Champ | Type | Défaut | Description |
|-------|------|--------|-------------|
| `url` | `str` | **requis** | URL du dépôt Git distant |
| `branch` | `str` | `"main"` | Branche cible |
| `zone_path` | `str` | `""` | Chemin relatif dans le dépôt contenant les fichiers de zone |
| `zone_file_suffix` | `str` | `".zone"` | Suffixe des fichiers de zone |
| `deploy_key_path` | `str` | `"/run/secrets/deploy_key"` | Chemin vers la clé SSH de déploiement |
| `known_hosts_path` | `Optional[str]` | `None` | Chemin vers le fichier known_hosts |
| `git_user_name` | `str` | `"acme-git-webhook"` | Nom pour les commits |
| `git_user_email` | `str` | `"webhook@example.com"` | Email pour les commits |

!!! tip "Résolution des zones"
    Le webhook résout la zone correcte en essayant des suffixes de domaine
    progressivement plus courts. Pour `_acme-challenge.sub.example.com`, il
    cherchera `sub.example.com.zone`, puis `example.com.zone`.

---

## `vault`

Stockage des certificats dans HashiCorp Vault via AppRole.

```yaml
vault:
  addr: "https://vault.example.com:8200"
  role_id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  secret_id_path: "/run/secrets/vault_secret_id"
  kv_mount: "secret"
  certs_path: "certs"
  verify: true
  skip: false
```

| Champ | Type | Défaut | Description |
|-------|------|--------|-------------|
| `addr` | `str` | **requis** | URL du serveur Vault |
| `role_id` | `str` | **requis** | Role ID AppRole |
| `secret_id_path` | `str` | `"/run/secrets/vault_secret_id"` | Chemin du fichier contenant le Secret ID |
| `kv_mount` | `str` | `"secret"` | Mount path du KV store |
| `certs_path` | `str` | `"certs"` | Chemin de base pour les certificats (`secret/certs/<domaine>/`) |
| `verify` | `bool` | `true` | Vérification TLS |
| `skip` | `bool` | `false` | Désactiver Vault (pour tests) |

!!! warning "Secret ID"
    Le `secret_id` est lu depuis un fichier au démarrage. Montez ce fichier
    via un secret Docker à l'emplacement configuré par `secret_id_path`.
    Ne jamais le placer dans le fichier YAML.

---

## `dns`

Configuration optionnelle de la vérification de propagation DNS.

```yaml
dns:
  nameservers:
    - "8.8.8.8"
    - "1.1.1.1"
  timeout: 120
  poll_interval: 5
  wait_for_propagation: true
```

| Champ | Type | Défaut | Description |
|-------|------|--------|-------------|
| `nameservers` | `list[str]` | `[]` | Serveurs DNS à interroger |
| `timeout` | `int` | `120` | Temps maximum d'attente (secondes) |
| `poll_interval` | `int` | `5` | Intervalle entre les sondages (secondes) |
| `wait_for_propagation` | `bool` | `false` | Activer l'attente de propagation dans `/acme/auth` |

Lorsque `wait_for_propagation` est `true`, l'endpoint `/acme/auth` sonde
automatiquement les serveurs DNS configurés après avoir poussé la modification
de zone et attend que l'enregistrement TXT soit visible (ou que le `timeout`
soit atteint).

---

## `openssl`

Options OpenSSL pour la conversion PFX.

```yaml
openssl:
  pfx_encryption: "aes256"
  pfx_digest: "sha256"
```

| Champ | Type | Défaut | Description |
|-------|------|--------|-------------|
| `pfx_encryption` | `str` | `"aes256"` | Algorithme de chiffrement PFX |
| `pfx_digest` | `str` | `"sha256"` | Algorithme de hachage PFX |

---

## `monitor`

Surveillance de l'expiration des certificats et renouvellement automatique.

```yaml
monitor:
  check_interval_hours: 24
  warn_days: [60, 30, 14, 7, 3, 1]
  alert_webhook_url: "https://hooks.slack.com/services/xxx"
  renew_command: "certbot renew --cert-name {domain} --config-dir /data/letsencrypt"
  renew_threshold: 14
```

| Champ | Type | Défaut | Description |
|-------|------|--------|-------------|
| `check_interval_hours` | `int` | `24` | Intervalle entre les vérifications (heures) |
| `warn_days` | `list[int]` | `[60, 30, 14, 7, 3, 1]` | Seuils d'alerte (jours avant expiration) |
| `alert_webhook_url` | `Optional[str]` | `None` | URL webhook pour les alertes (Slack, etc.) |
| `renew_command` | `Optional[str]` | `None` | Commande de renouvellement (supporte `{domain}`) |
| `renew_threshold` | `int` | `14` | Seuil de renouvellement automatique (jours) |

!!! info "Alertes"
    L'alerte envoyée au webhook est un POST JSON avec les champs :
    `domain`, `days_left`, `expiry_date`, `message`.

---

## `targets`

Liste des cibles de déploiement. Voir les pages dédiées pour chaque type :

- [F5 Big-IP](targets/f5.md)
- [Ivanti VPN](targets/ivanti.md)
- [Exchange SMTP](targets/exchange.md)
- [Cible personnalisée](targets/custom.md)

```yaml
targets:
  - name: "f5-paris"
    provider: "f5"
    addr: "https://bigip.example.com"
    username: "admin"
    password_path: "/run/secrets/f5_password"
    verify: true
    timeout: 60

  - name: "ivanti-vpn"
    provider: "ivanti"
    addr: "https://ivanti.example.com"
    api_key_path: "/run/secrets/ivanti_api_key"
    internal_ports: ["8443"]
    external_ports: ["443"]
    management_interface: false
    verify: true
    timeout: 120

  - name: "exchange-smtp"
    provider: "exchange"
    addr: "https://exchange.example.com:5986"
    transport: "ntlm"
    username: "DOMAIN\\svc-cert"
    password_path: "/run/secrets/exchange_password"
    remote_path: "C:\\certs"
    services: "SMTP"
    verify: true
    timeout: 180
```

!!! tip "Migration automatique"
    La configuration `f5` legacy (hors `targets`) est automatiquement migrée
    vers une cible nommée `f5` au démarrage si aucune section `targets`
    n'existe.
