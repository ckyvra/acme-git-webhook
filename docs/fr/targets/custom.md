# Cible personnalisée

Vous pouvez étendre acme-git-webhook en écrivant votre propre cible de
déploiement. Il suffit d'implémenter l'interface `DeployTarget` et
d'enregistrer la classe via le système de plugins.

## Interface `DeployTarget`

```python
from abc import ABC, abstractmethod
from typing import Any


class DeployTarget(ABC):
    """Interface pour une cible de déploiement de certificat."""

    @abstractmethod
    def deploy(
        self,
        domain: str,
        cert_pem: str,
        fullchain_pem: str,
        privkey_pem: str,
        chain_pem: str | None = None,
    ) -> dict[str, Any]:
        """Déploie le certificat sur la cible.

        Args:
            domain: Nom de domaine (ex. "example.com").
            cert_pem: Certificat PEM.
            fullchain_pem: Chaîne complète PEM.
            privkey_pem: Clé privée PEM.
            chain_pem: Chaîne d'intermédiaires PEM (optionnel).

        Returns:
            Dictionnaire avec au moins la clé "status" ("success" ou "error").
        """
        ...
```

## Exemple : cible WebDAV

```python
import requests
from pathlib import Path
from typing import Any

from acme_webhook.targets.base import DeployTarget


class WebDAVTarget(DeployTarget):
    """Déploie les certificats sur un serveur WebDAV."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.url = config["url"].rstrip("/")
        self.username = config["username"]
        self.password_path = Path(config["password_path"])

    def deploy(
        self,
        domain: str,
        cert_pem: str,
        fullchain_pem: str,
        privkey_pem: str,
        chain_pem: str | None = None,
    ) -> dict[str, Any]:
        password = self.password_path.read_text().strip()
        files = {
            f"{domain}/cert.pem": cert_pem,
            f"{domain}/fullchain.pem": fullchain_pem,
            f"{domain}/privkey.pem": privkey_pem,
        }
        for path, content in files.items():
            resp = requests.put(
                f"{self.url}/{path}",
                data=content,
                auth=(self.username, password),
            )
            resp.raise_for_status()
        return {"status": "success", "target": "webdav"}
```

## Enregistrement de la cible

Déclarez votre cible dans le point d'entrée `acme_webhook.targets` du
`pyproject.toml` ou `setup.py` :

```toml
# pyproject.toml
[project.entry-points."acme_webhook.targets"]
webdav = "myplugin.targets:WebDAVTarget"
```

## Configuration

Une fois enregistrée, utilisez-la dans `config.yaml` :

```yaml
targets:
  - name: "webdav-backup"
    provider: "webdav"
    url: "https://webdav.example.com/certs"
    username: "certbot"
    password_path: "/run/secrets/webdav_password"
```

| Champ | Type | Défaut | Description |
|-------|------|--------|-------------|
| `name` | `str` | — | Identifiant unique de la cible |
| `provider` | `str` | — | Identifiant du plugin (doit correspondre à l'entrée `entry_points`) |
| (autres) | — | — | Champs propres à votre implémentation |

Le dictionnaire `config` passé au constructeur contient l'intégralité
de la configuration YAML de la cible, y compris les champs spécifiques
que vous définissez.
