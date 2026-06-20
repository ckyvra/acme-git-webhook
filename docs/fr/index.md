# cert-renew

[![ci](https://github.com/ckyvra/cert-renew/actions/workflows/ci.yml/badge.svg)](https://github.com/ckyvra/cert-renew/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/ckyvra/cert-renew/branch/main/graph/badge.svg)](https://codecov.io/gh/ckyvra/cert-renew)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ckyvra/cert-renew/badge)](https://scorecard.dev/viewer/?uri=github.com/ckyvra/cert-renew)
[![version](https://img.shields.io/github/v/tag/ckyvra/cert-renew?label=version)](https://github.com/ckyvra/cert-renew/tags)
[![ghcr](https://img.shields.io/badge/GHCR-latest-blue?logo=docker)](https://github.com/ckyvra/cert-renew/pkgs/container/cert-renew)

Webhook FastAPI qui provisionne les défis ACME DNS-01 en ajoutant/supprimant
des enregistrements TXT dans des fichiers de zone Bind stockés dans un dépôt Git,
déploie optionnellement les certificats vers F5 Big-IP, Ivanti VPN, Exchange SMTP
(ou toute cible personnalisée via l'interface `DeployTarget`) et surveille
l'expiration.

## Fonctionnement

```mermaid
flowchart LR
    ACME["Client ACME<br/>(certbot / acme.sh)"] -->|POST /acme/auth| WH["cert-renew"]
    ACME -->|POST /acme/cleanup| WH
    ACME -->|POST /acme/deploy| WH

    WH -->|git push| GIT["Dépôt GitHub<br/>(zones Bind)"]
    WH -->|store cert| VAULT["HashiCorp Vault<br/>secret/certs/{domain}/"]

    VAULT -->|déploiement| F5["F5 Big-IP<br/>iControl REST"]
    VAULT -->|déploiement| IV["Ivanti VPN<br/>REST API"]
    VAULT -->|déploiement| EX["Exchange SMTP<br/>WinRM / PowerShell"]
    VAULT -->|surveillance| MON["CertMonitor<br/>APScheduler"]

    MON -->|alerte| ALERT["Webhook<br/>(Slack, etc.)"]
    MON -->|renouvellement auto| ACME
```

## Fonctionnalités clés

- **DNS-01 automatisé** — Le client ACME appelle le webhook en trois phases :
  `auth` (injection TXT), `cleanup` (suppression), `deploy` (stockage Vault).
- **Zones Bind dans Git** — Les fichiers de zone sont versionnés et poussés
  vers un dépôt Git. Idéal pour les pipelines GitOps.
- **Propagation DNS automatique** — Interrogation des serveurs DNS configurés
  jusqu'à ce que l'enregistrement TXT soit visible (optionnel).
- **Stockage Vault** — Les certificats émis sont stockés dans HashiCorp Vault
  via AppRole, avec le secret_id chargé depuis un fichier (jamais dans la config).
- **Cibles de déploiement multiples** — Déploiement vers F5 Big-IP, Ivanti VPN,
  Exchange SMTP, ou cible personnalisée via une interface Python.
- **Routage par domaine** — Chaque domaine peut être déployé vers un sous-ensemble
  de cibles, configurable dynamiquement via l'API.
- **Surveillance d'expiration** — Vérification périodique des certificats dans
  Vault, alertes via webhook Slack/HTTP, renouvellement automatique.
- **Wildcards** — Support complet des domaines wildcard (`*.example.com`) pour
  le DNS, Vault, F5, Ivanti et Exchange.
- **GlobalSign Atlas** — Support de l'External Account Binding (EAB) pour
  l'autorité de certification GlobalSign.

## Technologies

| Composant | Technologie |
|-----------|-------------|
| Framework | FastAPI (Python) |
| DNS | dnspython, fichiers de zone Bind |
| Git | GitPython, dépôt distant |
| Stockage | HashiCorp Vault (KV v2) |
| Déploiement | iControl REST, Ivanti REST API, WinRM/PowerShell |
| Conteneurisation | Docker, Docker Compose, Helm |
| CI | GitHub Actions |
