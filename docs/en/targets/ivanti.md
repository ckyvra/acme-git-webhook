# Ivanti VPN target

Deploys certificates to Ivanti Connect Secure (VPN) appliances via the Ivanti REST API.

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

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | `str` | **required** | Unique identifier for this target. |
| `provider` | `str` | `"ivanti"` | Must be `"ivanti"`. |
| `addr` | `str` | **required** | Base URL of the Ivanti REST API. |
| `api_key_path` | `str` | **required** | Path to a file containing the API key (mounted secret). |
| `verify` | `bool` | `true` | Verify the Ivanti TLS certificate. |
| `internal_ports` | `list[str]` | `[]` | Internal interfaces to bind the certificate (e.g. `["8443"]`). |
| `external_ports` | `list[str]` | `[]` | External interfaces to bind the certificate (e.g. `["443"]`). |
| `management_interface` | `bool` | `false` | Also bind to the management interface. |
| `timeout` | `int` | `60` | HTTP request timeout in seconds. |

## How it works

### 1. Convert PEM to PFX

Uses the `cryptography` library to convert the PEM fullchain + private key to PKCS#12 (PFX) format with a randomly generated password:

```python
from app.targets._crypto import pem_to_pfx

pfx_bytes, password = pem_to_pfx(fullchain_pem, privkey_pem)
# password = "aB3x...random...24chars"
```

The password is generated via `secrets.token_urlsafe(24)` — it is regenerated on every deployment and **never stored**.

### 2. Upload to Ivanti

The PFX is base64-encoded and sent to:

```
POST /api/v1/system/certificates/device-certificates
```

Payload:

```json
{
  "cert": "<base64-encoded PFX>",
  "password": "<random password>",
  "internalPorts": ["8443"],
  "externalPorts": ["443"],
  "managementInterface": false
}
```

### 3. Port binding

The `internal_ports`, `external_ports`, and `management_interface` fields control which Ivanti listener interfaces receive the new certificate. At least one port should be configured for a meaningful deployment.

## Result

```json
{
  "target": "ivanti-vpn",
  "provider": "ivanti",
  "status": "ok",
  "details": {
    "host": "https://ivanti.example.com",
    "internal_ports": ["8443"],
    "external_ports": ["443"]
  }
}
```
