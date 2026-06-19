import logging
import os
from pathlib import Path
from typing import Annotated, Literal, Union

import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class AuthConfig(BaseModel):
    """Authentication configuration.

    Attributes:
        api_keys: List of accepted Bearer tokens. Any client request
            carrying one of these keys in the Authorization header will
            be allowed to trigger add/remove operations.
    """
    api_keys: list[str]


class WebhookConfig(BaseModel):
    """Webhook server configuration.

    Attributes:
        bind: Host and port the FastAPI server listens on
            (default: 0.0.0.0:8000).
        work_dir: Local directory used for cloning the zone repository
            and storing the inter-process lock file.
        ssh_key: Path to a deploy SSH key (mounted file or secret).
            When set, GitPython is configured to use this key for
            authentication instead of the default SSH agent.
    """
    bind: str = "0.0.0.0:8000"
    work_dir: str = "/data/acme-git-webhook"
    ssh_key: str | None = None


class RepoConfig(BaseModel):
    """Git repository layout for Bind zone files.

    Attributes:
        url: SSH or HTTPS remote URL of the zone repository.
        branch: Git branch to clone and push to (default: main).
        zone_path: Subdirectory within the repo where .zone files
            are stored (e.g. "zones"). Use "." for the repo root.
        zone_file_suffix: File extension of Bind zone files
            (default: .zone).
    """
    url: str
    branch: str = "main"
    zone_path: str = "."
    zone_file_suffix: str = ".zone"


class VaultConfig(BaseModel):
    """Vault server configuration for secure certificate storage.

    The webhook authenticates to Vault via AppRole and stores
    Let's Encrypt certificates in the KV secrets engine.

    Attributes:
        addr: URL of the Vault server (e.g. https://vault.example.com:8200).
        role_id: AppRole RoleID used for authentication.
        secret_id_path: Path to a file containing the AppRole SecretID.
            The file is read at runtime so the SecretID is never baked
            into the config file.
        kv_mount: Mount path of the KV secrets engine (default: "secret").
        certs_path: Base path under which certificates are stored
            (default: "certs"). The full path becomes
            ``<kv_mount>/<certs_path>/<domain>/...``.
        verify: Whether to verify the Vault TLS certificate
            (default: True).
        skip: When True, all Vault operations are silently skipped.
            Useful for local development and tests when no Vault
            server is available (default: False).
    """
    addr: str
    role_id: str
    secret_id_path: str
    kv_mount: str = "secret"
    certs_path: str = "certs"
    verify: bool = True
    skip: bool = False


class F5HostConfig(BaseModel):
    addr: str
    username: str
    password_path: str
    verify: bool = True


class F5Config(BaseModel):
    hosts: list[F5HostConfig]


class F5TargetConfig(BaseModel):
    """Configuration for a single F5 Big-IP deployment target.

    Attributes:
        name: Unique identifier used to reference this target in API calls.
        provider: Discriminator — must be ``"f5"``.
        addr: Base URL of the F5 iControl REST endpoint.
        username: F5 admin username.
        password_path: Path to a file containing the F5 password.
        verify: Whether to verify the F5 TLS certificate (default: True).
        timeout: HTTP request timeout in seconds (default: 30).
    """
    name: str
    provider: Literal["f5"] = "f5"
    addr: str
    username: str
    password_path: str
    verify: bool = True
    timeout: int = 30


class IvantiTargetConfig(BaseModel):
    """Configuration for an Ivanti Connect Secure (VPN) deployment target.

    Attributes:
        name: Unique identifier used to reference this target in API calls.
        provider: Discriminator — must be ``"ivanti"``.
        addr: Base URL of the Ivanti REST API endpoint.
        api_key_path: Path to a file containing the API key.
        verify: Whether to verify the Ivanti TLS certificate (default: True).
        internal_ports: Internal interfaces to bind the certificate to.
        external_ports: External interfaces to bind the certificate to.
        management_interface: Whether to also bind to the management interface.
        timeout: HTTP request timeout in seconds (default: 60).
    """
    name: str
    provider: Literal["ivanti"] = "ivanti"
    addr: str
    api_key_path: str
    verify: bool = True
    internal_ports: list[str] = []
    external_ports: list[str] = []
    management_interface: bool = False
    timeout: int = 60


class ExchangeTargetConfig(BaseModel):
    """Configuration for an Exchange SMTP deployment target (WinRM).

    Attributes:
        name: Unique identifier used to reference this target in API calls.
        provider: Discriminator — must be ``"exchange"``.
        addr: WinRM endpoint URL (e.g. ``https://exchange.example.com:5986``).
        transport: WinRM authentication transport (``"ntlm"`` or ``"kerberos"``).
        username: WinRM username (domain format: ``DOMAIN\\user``).
        password_path: Path to a file containing the WinRM password.
        verify: Whether to verify the WinRM TLS certificate (default: True).
        remote_path: Remote directory for staging the PFX file.
        services: Exchange services to enable (default: ``"SMTP"``).
        timeout: WinRM operation timeout in seconds (default: 120).
    """
    name: str
    provider: Literal["exchange"] = "exchange"
    addr: str
    transport: Literal["ntlm", "kerberos"] = "ntlm"
    username: str
    password_path: str
    verify: bool = True
    remote_path: str = "C:\\certs"
    services: str = "SMTP"
    timeout: int = 120


# Discriminated union so Pydantic selects the correct model based on
# the value of the ``provider`` field in the YAML configuration.
TargetConfig = Annotated[
    Union[F5TargetConfig, IvantiTargetConfig, ExchangeTargetConfig],
    Field(discriminator="provider"),
]


class DnsConfig(BaseModel):
    nameservers: list[str] = ["8.8.8.8", "1.1.1.1"]
    timeout: int = 120
    poll_interval: int = 5
    wait_for_propagation: bool = False


class PostQuantumConfig(BaseModel):
    enabled: bool = False
    hybrid_mode: bool = True


class OpensslConfig(BaseModel):
    key_algorithm: Literal["rsa", "ecdsa", "ed25519"] = "ecdsa"
    rsa_key_size: int = 4096
    ecdsa_curve: Literal["secp256r1", "secp384r1", "secp521r1"] = "secp384r1"
    signature_hash: Literal["sha256", "sha384", "sha512"] = "sha384"
    post_quantum: PostQuantumConfig | None = None


class MonitorConfig(BaseModel):
    check_interval_hours: int = 24
    warn_days: list[int] = [60, 30, 14, 7, 3, 1]
    alert_webhook_url: str | None = None
    alert_webhook_headers: dict[str, str] | None = None
    renew_command: str | None = None
    renew_timeout: int = 300
    renew_threshold: int = 14
    renew_percentage: int | None = None


class AppConfig(BaseModel):
    """Top-level application configuration.

    Groups authentication, webhook server, repository and Vault
    settings into a single validated object loaded from config.yaml.
    """
    auth: AuthConfig
    webhook: WebhookConfig
    repo: RepoConfig
    vault: VaultConfig | None = None
    f5: F5Config | None = None
    dns: DnsConfig | None = None
    monitor: MonitorConfig | None = None
    targets: list[TargetConfig] | None = None
    openssl: OpensslConfig | None = None


def load_config(path: str | None = None) -> AppConfig:
    """Load and validate the YAML configuration file.

    Resolves the config path from the CONFIG_PATH environment variable
    first, then falls back to "config.yaml" in the working directory.

    Args:
        path: Optional explicit path to the configuration file.
            If None, the environment variable or default is used.

    Returns:
        A validated AppConfig instance.

    Raises:
        FileNotFoundError: If the config file does not exist.
        pydantic.ValidationError: If the YAML content does not match
            the expected schema.
    """
    if path is None:
        path = os.getenv("CONFIG_PATH", "config.yaml")
    with open(path) as f:
        data = yaml.safe_load(f)
    cfg = AppConfig.model_validate(data)
    if cfg.vault and not cfg.vault.verify:
        logger.warning(
            "Vault TLS verification is DISABLED (verify=False) — "
            "this is insecure and should only be used for development"
        )
    return cfg
