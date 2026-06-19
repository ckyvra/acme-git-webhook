# Cible : Ivanti VPN

Déploie les certificats sur un concentrateur VPN Ivanti (Pulse Secure)
via l'API REST.

## Configuration

```yaml
targets:
  - name: "ivanti-vpn"
    provider: "ivanti"
    addr: "https://ivanti.example.com"
    api_key_path: "/run/secrets/ivanti_api_key"
    internal_ports: ["8443"]
    external_ports: ["443"]
    management_interface: false
    verify: true
    timeout: 120
```

| Champ | Type | Défaut | Description |
|-------|------|--------|-------------|
| `name` | `str` | — | Identifiant unique de la cible |
| `provider` | `str` | — | `"ivanti"` |
| `addr` | `str` | — | URL du concentrateur VPN |
| `api_key_path` | `str` | `"/run/secrets/ivanti_api_key"` | Chemin du fichier contenant la clé API |
| `internal_ports` | `list[str]` | `["8443"]` | Ports internes à associer au certificat |
| `external_ports` | `list[str]` | `["443"]` | Ports externes à associer au certificat |
| `management_interface` | `bool` | `false` | Appliquer le certificat à l'interface de management |
| `verify` | `bool` | `true` | Vérification TLS |
| `timeout` | `int` | `120` | Timeout HTTP (secondes) |

## Fonctionnement

1. **Conversion PFX** — Le certificat PEM est converti au format PFX
   avec un mot de passe aléatoire (généré à chaque déploiement).
2. **Upload** — Envoi du PFX vers l'API REST Ivanti :
   `POST /api/v1/system/certificates/device-certificates`.
3. **Association** — Le certificat est associé aux ports internes
   et externes configurés.

!!! security "Mot de passe PFX"
    Le mot de passe PFX est généré aléatoirement à chaque déploiement
    et n'est jamais persistanté ni stocké.

## Exemple de déploiement

```bash
curl -X POST http://localhost:8000/deploy/example.com/ivanti-vpn \
  -H "Authorization: Bearer sk-XXXXXXXXXXXX"
```

## Vérification

```bash
# Via l'API REST Ivanti
curl -sk -H "Authorization: Bearer $(cat /run/secrets/ivanti_api_key)" \
  "https://ivanti.example.com/api/v1/system/certificates/device-certificates"
```
