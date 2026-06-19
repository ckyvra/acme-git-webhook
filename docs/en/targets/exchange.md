# Exchange SMTP target

Deploys certificates to Microsoft Exchange via WinRM and PowerShell for SMTP (or custom service) binding.

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

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | `str` | **required** | Unique identifier for this target. |
| `provider` | `str` | `"exchange"` | Must be `"exchange"`. |
| `addr` | `str` | **required** | WinRM endpoint URL (typically HTTPS on port 5986). |
| `transport` | `str` | `"ntlm"` | WinRM authentication: `"ntlm"` or `"kerberos"`. |
| `username` | `str` | **required** | WinRM username in domain format (`DOMAIN\\user`). |
| `password_path` | `str` | **required** | Path to a file containing the WinRM password (mounted secret). |
| `verify` | `bool` | `true` | Verify the WinRM TLS certificate. |
| `remote_path` | `str` | `"C:\\certs"` | Remote directory for staging the PFX file. |
| `services` | `str` | `"SMTP"` | Exchange services to enable (e.g. `"SMTP"`, `"SMTP,IMAP"`, `"IIS"`). |
| `timeout` | `int` | `120` | WinRM operation timeout in seconds. |

## How it works

The Exchange target requires `pywinrm` (`pip install pywinrm`).

### 1. Convert PEM to PFX

The PEM fullchain and private key are converted to PKCS#12 (PFX) format with a random password via `app.targets._crypto.pem_to_pfx`. The PFX is base64-encoded for transport.

### 2. Upload PFX via WinRM

The base64-encoded PFX is sent to the Exchange server using a PowerShell one-liner that decodes and writes it:

```powershell
$bytes = [Convert]::FromBase64String("<base64>");
[IO.File]::WriteAllBytes("C:\certs\example.com.pfx", $bytes)
```

### 3. Import and enable for Exchange

A second PowerShell command imports the PFX into the Exchange certificate store and enables it for the configured services:

```powershell
$pwd = ConvertTo-SecureString "<password>" -AsPlainText -Force;
$cert = Import-ExchangeCertificate -FileName "C:\certs\example.com.pfx" -Password $pwd;
Enable-ExchangeCertificate -Thumbprint $cert.Thumbprint -Services SMTP
```

### 4. Cleanup

The remote PFX file is removed after import:

```powershell
Remove-Item -Path "C:\certs\example.com.pfx" -Force -ErrorAction SilentlyContinue
```

## Wildcard handling

Wildcard domains are handled natively by the X.509 certificate SAN. Exchange imports the PFX and binds the certificate — no special name transformation is needed.

## Requirements

- Exchange must be configured to accept WinRM connections (port 5986 / HTTPS). See `winrm quickconfig` on the Exchange server.
- The service account used for WinRM must have Exchange administrative privileges to run `Import-ExchangeCertificate` and `Enable-ExchangeCertificate`.
- `pywinrm` must be installed in the webhook environment.

## Result

```json
{
  "target": "exchange-smtp",
  "provider": "exchange",
  "status": "ok",
  "details": {
    "host": "https://exchange.example.com:5986",
    "services": "SMTP",
    "remote_path": "C:\\certs\\example.com.pfx"
  }
}
```
