# Développement

## Prérequis

- Python 3.11+
- Poetry ou pip
- Git

## Installation

```bash
# Cloner le dépôt
git clone https://github.com/ckyvra/acme-git-webhook.git
cd acme-git-webhook

# Créer l'environnement virtuel et installer les dépendances
python -m venv .venv
source .venv/bin/activate
pip install -r dev-requirements.txt
```

Ou via les Makefile :

```bash
make install   # installe les dépendances
```

## Tests

```bash
# Exécuter tous les tests unitaires
make test

# Ou directement avec pytest
.venv/bin/python -m pytest -v

# Avec couverture
.venv/bin/python -m pytest --cov=app -v

# Tests d'intégration (nécessite Docker et réseau)
make test-integration
.venv/bin/python -m pytest --run-integration -v
```

!!! tip "Nouveaux tests"
    Chaque nouveau module doit avoir son fichier de test couvrant :
    - Configuration valide (valeurs par défaut et personnalisées)
    - Configuration invalide (erreurs de validation)
    - Cas limites (None, vide, manquant)
    - Intégration avec les composants existants

## Lint

```bash
make lint
```

## Vérification complète

```bash
make check   # lint + tests
```

## Structure du projet

```
acme-git-webhook/
├── acme_webhook/
│   ├── __init__.py
│   ├── main.py              # Application FastAPI
│   ├── config.py            # Modèles Pydantic
│   ├── acme.py              # Logique ACME (auth/cleanup/deploy)
│   ├── dns.py               # Manipulation des zones Bind
│   ├── git_.py              # Opérations Git
│   ├── vault.py             # Interface Vault
│   ├── monitor.py           # Surveillance certificats
│   ├── targets/
│   │   ├── __init__.py
│   │   ├── base.py          # Interface DeployTarget
│   │   ├── f5.py
│   │   ├── ivanti.py
│   │   └── exchange.py
│   └── utils/
│       ├── __init__.py
│       └── crypto.py        # Conversion PEM/PFX
├── tests/
│   ├── conftest.py              # Fixtures partagées (+ option --run-integration)
│   ├── test_config.py
│   ├── test_main.py
│   ├── test_zone_handler.py
│   ├── test_git_handler.py
│   ├── test_vault_handler.py
│   ├── test_dns_probe.py
│   ├── test_cert_monitor.py
│   ├── test_integration.py      # Tests d'intégration DNS/Vault
│   ├── test_targets_f5.py
│   ├── test_targets_ivanti.py
│   ├── test_targets_exchange.py
│   ├── test_targets_crypto.py
│   └── test_targets_manager.py
├── helm/
│   └── ...
├── docs/
│   ├── en/
│   └── fr/
├── scripts/
│   └── register-acme.sh     # Enregistrement GlobalSign EAB
├── config.yaml              # Exemple de configuration
├── docker-compose.yml       # Déploiement Docker
├── Dockerfile
├── Makefile
├── mkdocs.yml
├── pyproject.toml
└── README.md
```

## Commandes Makefile

| Commande | Description |
|----------|-------------|
| `make install` | Crée le venv et installe les dépendances |
| `make test` | Exécute les tests unitaires |
| `make test-integration` | Exécute tous les tests (y compris intégration) |
| `make lint` | Vérifie la syntaxe et le style |
| `make check` | Exécute lint + test |
| `make clean` | Supprime le venv et les caches |
| `make docs` | Construit la documentation MkDocs |

## Conventions de code

- Toutes les méthodes publiques doivent avoir des annotations de type.
- Les méthodes privées sont préfixées par `_`.
- Les nouveaux champs de configuration doivent être optionnels avec
  des valeurs par défaut.
- La rétrocompatibilité doit être maintenue.

## Documentation locale

```bash
# Construire et servir la documentation MkDocs
mkdocs serve

# Construire la documentation statique
mkdocs build
```

## Créer une cible personnalisée

Voir la page [Cible personnalisée](targets/custom.md) pour le guide
complet sur l'implémentation d'un nouveau `DeployTarget`.
