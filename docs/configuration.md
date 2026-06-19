# Configuration

The application is configured via a single `config.yaml` file. The path is read from the `CONFIG_PATH` environment variable (defaults to `config.yaml` in the working directory).

## `auth`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `api_keys` | `list[str]` | **required** | Accepted Bearer tokens. Generate with `python -c "import secrets; print(secrets.token_urlsafe(32))"`. An additional key can be set via the `ACME_WEBHOOK_API_KEY` environment variable. |

## `webhook`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bind` | `str` | `"0.0.0.0:8000"` | Host and port the FastAPI server listens on. |
| `work_dir` | `str` | `"/data/acme-git-webhook"` | Local directory for cloning the zone repository and storing the inter-process lock file. |
| `ssh_key` | `str` | `null` | Path to a deploy SSH key (mounted file). When set, GitPython uses this key instead of the default SSH agent. |

## `repo`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | `str` | **required** | SSH or HTTPS remote URL of the zone repository. |
| `branch` | `str` | `"main"` | Git branch to clone and push to. |
| `zone_path` | `str` | `"."` | Subdirectory within the repo where `.zone` files are stored. Use `"."` for the repo root. |
| `zone_file_suffix` | `str` | `".zone"` | File extension of Bind zone files. |

Zone resolution: the webhook strips the `_acme-challenge.` prefix then tries progressively shorter domain suffixes to find a matching zone file. E.g. `_acme-challenge.sub.example.com` looks for `sub.example.com.zone`, then `example.com.zone`.

## `vault`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `addr` | `str` | **required** | URL of the Vault server (e.g. `https://vault.example.com:8200`). |
| `role_id` | `str` | **required** | AppRole RoleID for authentication. |
| `secret_id_path` | `str` | **required** | Path to a file containing the AppRole SecretID (read at runtime, never baked into config). |
| `kv_mount` | `str` | `"secret"` | Mount path of the KV secrets engine. |
| `certs_path` | `str` | `"certs"` | Base path for certificates. Full path becomes `<kv_mount>/<certs_path>/<domain>/...`. |
| `verify` | `bool` | `true` | Whether to verify the Vault TLS certificate. |
| `skip` | `bool` | `false` | When `true`, all Vault operations are silently skipped (useful for development). |

## `dns`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `nameservers` | `list[str]` | `["8.8.8.8", "1.1.1.1"]` | DNS resolvers to query for propagation checking. Private/loopback/multicast IPs are rejected. |
| `timeout` | `int` | `120` | Maximum time in seconds to wait for propagation. |
| `poll_interval` | `int` | `5` | Seconds between polling rounds. |
| `wait_for_propagation` | `bool` | `false` | When `true`, `/acme/auth` automatically waits for propagation before returning. |

### Propagation behaviour

When `wait_for_propagation` is `true`, the `/acme/auth` endpoint:

1. Pushes the zone file change to Git
2. Polls each configured nameserver until every server returns the expected TXT value
3. Returns a `propagation` field (`"propagated"` or `"timeout"`) along with matched/pending nameserver lists and elapsed time

## `openssl`

Controls cryptographic parameters exposed as template variables for the `monitor.renew_command` (`{key_type}`, `{key_size}`, `{curve}`, `{sig_hash}`).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `key_algorithm` | `str` | `"ecdsa"` | Key type: `"rsa"`, `"ecdsa"`, or `"ed25519"`. |
| `rsa_key_size` | `int` | `4096` | RSA key size (used when `key_algorithm` is `"rsa"`). |
| `ecdsa_curve` | `str` | `"secp384r1"` | ECDSA curve: `"secp256r1"`, `"secp384r1"`, or `"secp521r1"`. |
| `signature_hash` | `str` | `"sha384"` | Signature hash: `"sha256"`, `"sha384"`, or `"sha512"`. |
| `post_quantum` | `dict` | `null` | Post-quantum cryptography settings (see below). |

### `post_quantum`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable post-quantum key exchange. |
| `hybrid_mode` | `bool` | `true` | Use hybrid (classical + post-quantum) mode. |

## `monitor`

See the [Monitoring](monitoring.md) page for full details.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `check_interval_hours` | `int` | `24` | How often to scan Vault for expiring certificates. |
| `warn_days` | `list[int]` | `[60, 30, 14, 7, 3, 1]` | Thresholds for warning alerts (descending). Each threshold fires once per certificate. |
| `alert_webhook_url` | `str` | `null` | URL for Slack-compatible JSON POST alerts. |
| `alert_webhook_headers` | `dict` | `null` | Optional custom headers for the alert webhook. |
| `renew_command` | `str` | `null` | Shell command to renew a certificate. `{domain}` is replaced at runtime. Supports `{key_type}`, `{key_size}`, `{curve}`, `{sig_hash}` from `openssl` config. |
| `renew_timeout` | `int` | `300` | Max seconds for renewal command execution. |
| `renew_threshold` | `int` | `14` | Days before expiry to trigger auto-renewal. |

## Deploy targets

Each target is a dictionary in the `targets` list. The `provider` field selects the implementation.

### Common fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | `str` | Unique identifier for this target (used in API paths like `/deploy/{domain}/{name}`). |
| `provider` | `str` | One of `"f5"`, `"ivanti"`, `"exchange"`. |

### F5 (`provider: "f5"`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `addr` | `str` | **required** | Base URL of the F5 iControl REST endpoint. |
| `username` | `str` | **required** | F5 admin username. |
| `password_path` | `str` | **required** | Path to a file containing the F5 password. |
| `verify` | `bool` | `true` | Verify the F5 TLS certificate. |
| `timeout` | `int` | `30` | HTTP request timeout in seconds. |

### Ivanti (`provider: "ivanti"`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `addr` | `str` | **required** | Base URL of the Ivanti REST API endpoint. |
| `api_key_path` | `str` | **required** | Path to a file containing the API key. |
| `verify` | `bool` | `true` | Verify the Ivanti TLS certificate. |
| `internal_ports` | `list[str]` | `[]` | Internal interfaces to bind the certificate to. |
| `external_ports` | `list[str]` | `[]` | External interfaces to bind the certificate to. |
| `management_interface` | `bool` | `false` | Also bind to the management interface. |
| `timeout` | `int` | `60` | HTTP request timeout in seconds. |

### Exchange (`provider: "exchange"`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `addr` | `str` | **required** | WinRM endpoint URL (e.g. `https://exchange.example.com:5986`). |
| `transport` | `str` | `"ntlm"` | WinRM authentication: `"ntlm"` or `"kerberos"`. |
| `username` | `str` | **required** | WinRM username in domain format (`DOMAIN\\user`). |
| `password_path` | `str` | **required** | Path to a file containing the WinRM password. |
| `verify` | `bool` | `true` | Verify the WinRM TLS certificate. |
| `remote_path` | `str` | `"C:\\certs"` | Remote directory for staging the PFX file. |
| `services` | `str` | `"SMTP"` | Exchange services to enable (e.g. `"SMTP,IMAP"`). |
| `timeout` | `int` | `120` | WinRM operation timeout in seconds. |

### Legacy `f5` section (removed)

The legacy `f5:` config section was removed in favour of the unified `targets:` list. Migrate any existing `f5:` config to:

```yaml
targets:
  - provider: f5
    name: bigip
    addr: "https://bigip.example.com"
    username: "admin"
    password_path: "/run/secrets/f5_password"
    verify: true
    timeout: 30
```
