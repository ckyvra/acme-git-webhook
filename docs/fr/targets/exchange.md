# Cible : Exchange SMTP

Déploie les certificats sur un serveur Microsoft Exchange via WinRM
et PowerShell pour activer le certificat sur le service SMTP.

## Configuration

```yaml
targets:
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

| Champ | Type | Défaut | Description |
|-------|------|--------|-------------|
| `name` | `str` | — | Identifiant unique de la cible |
| `provider` | `str` | — | `"exchange"` |
| `addr` | `str` | — | URL WinRM du serveur Exchange (port 5986) |
| `transport` | `str` | `"ntlm"` | Protocole d'authentification WinRM |
| `username` | `str` | — | Compte de service (format `DOMAINE\\utilisateur`) |
| `password_path` | `str` | `"/run/secrets/exchange_password"` | Chemin du fichier contenant le mot de passe |
| `remote_path` | `str` | `"C:\\certs"` | Chemin distant de copie du PFX |
| `services` | `str` | `"SMTP"` | Services Exchange à activer (ex. `"SMTP,IMAP"`) |
| `verify` | `bool` | `true` | Vérification TLS |
| `timeout` | `int` | `180` | Timeout WinRM (secondes) |

## Fonctionnement

1. **Conversion PFX** — Le certificat PEM est converti au format PFX
   avec un mot de passe aléatoire.
2. **Copie distante** — Le fichier PFX est copié vers le serveur Exchange
   via WinRM à l'emplacement `remote_path`.
3. **Importation PowerShell** — Exécution de la commande PowerShell
   d'import et d'activation :

```powershell
Import-ExchangeCertificate -FileName "C:\certs\example.pfx" `
  -Password (ConvertTo-SecureString -String '<password>' -AsPlainText -Force) `
  | Enable-ExchangeCertificate -Services SMTP
```

## Exemple de déploiement

```bash
curl -X POST http://localhost:8000/deploy/example.com/exchange-smtp \
  -H "Authorization: Bearer sk-XXXXXXXXXXXX"
```

## Vérification

```powershell
# Sur le serveur Exchange
Get-ExchangeCertificate | Where-Object {$_.Services -match "SMTP"} | Format-List
```
