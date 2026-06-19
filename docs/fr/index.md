# acme-git-webhook

[![ci](https://github.com/ckyvra/acme-git-webhook/actions/workflows/ci.yml/badge.svg)](https://github.com/ckyvra/acme-git-webhook/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/ckyvra/acme-git-webhook/branch/main/graph/badge.svg)](https://codecov.io/gh/ckyvra/acme-git-webhook)
[![version](https://img.shields.io/github/v/tag/ckyvra/acme-git-webhook?label=version)](https://github.com/ckyvra/acme-git-webhook/tags)
[![ghcr](https://img.shields.io/badge/GHCR-latest-blue?logo=docker)](https://github.com/ckyvra/acme-git-webhook/pkgs/container/acme-git-webhook)

Webhook FastAPI qui provisionne les défis ACME DNS-01 en ajoutant/supprimant
des enregistrements TXT dans des fichiers de zone Bind stockés dans un dépôt Git,
déploie optionnellement les certificats vers F5 Big-IP, Ivanti VPN, Exchange SMTP
(ou toute cible personnalisée via l'interface `DeployTarget`) et surveille
l'expiration.

## Fonctionnement

```
Client ACME (certbot/acme.sh)
        │
        │  POST /acme/auth { domain, validation }
        │  POST /acme/cleanup { domain }
        │  POST /acme/deploy { domain, cert_pem, ... }
        ▼
acme-git-webhook
        │
        │  1. git pull
        │  2. dnspython: mise à jour du fichier de zone
        │  3. git commit + push
        │  4. Vérification propagation DNS (optionnelle, automatique)
        │  5. Vault : stockage du certificat
        │  6. Cibles de déploiement : F5, Ivanti, Exchange… (optionnel)
        │  7. Surveillance : vérification expiration + renouvellement auto (optionnel)
        ├──────────────────────┬───────────────────────┬──────────────────────┐
        ▼                      ▼                       ▼                      ▼
Dépôt GitHub           HashiCorp Vault          Cibles (F5 / Ivanti /    Logs / Webhook
(zones Bind)           (KV store)               Exchange / personnalisée) (alerte expiration)
        │                      │                       │
        │  CI/CD               │  Récupération par     │  Profil SSL mis à jour
        ▼                      ▼                       ▼
DNS faisant autorité    secret/certs/          /Common/example.com
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
