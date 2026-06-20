import logging
import os
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from zoneinfo import ZoneInfo

import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class DeployWindow(BaseModel):
    """Time window during which certificate renewal and deployment are allowed.

    When configured, renewal (via CertMonitor) and deployment to targets
    will only proceed if the current time falls within the window on an
    allowed day. Outside the window, operations are deferred to the next
    window opening.

    Attributes:
        start: Window opening time in ``HH:MM`` 24-hour format (e.g. ``"08:00"``).
        end: Window closing time in ``HH:MM`` 24-hour format (e.g. ``"18:00"``).
            Supports wrapping past midnight (e.g. ``"22:00"`` → ``"06:00"``).
        days: Days of the week the window applies to, where ``1`` = Monday
            and ``7`` = Sunday (default: all days).
        timezone: IANA timezone name (e.g. ``"Europe/Paris"``, ``"America/New_York"``).
    """

    start: str
    end: str
    days: list[int] = Field(default=[1, 2, 3, 4, 5, 6, 7])
    timezone: str = "UTC"


def _window_start_end(
    window: DeployWindow,
    dt: datetime,
) -> tuple[datetime, datetime]:
    """Return the (start, end) datetimes for the current day in the window's timezone."""
    tz = ZoneInfo(window.timezone)
    local = dt.astimezone(tz)
    start_h, start_m = map(int, window.start.split(":"))
    end_h, end_m = map(int, window.end.split(":"))
    day_start = local.replace(hour=0, minute=0, second=0, microsecond=0)
    win_start = day_start.replace(hour=start_h, minute=start_m)
    win_end = day_start.replace(hour=end_h, minute=end_m)
    return win_start, win_end


def is_within_window(window: DeployWindow, dt: datetime | None = None) -> bool:
    """Check whether *dt* falls within the deploy window."""
    if dt is None:
        dt = datetime.now(UTC)
    tz = ZoneInfo(window.timezone)
    local = dt.astimezone(tz)

    if local.isoweekday() not in window.days:
        return False

    win_start, win_end = _window_start_end(window, dt)
    start_h, start_m = map(int, window.start.split(":"))
    end_h, end_m = map(int, window.end.split(":"))
    wraps = start_h > end_h or (start_h == end_h and start_m > end_m)

    if wraps:
        return local >= win_start or local < win_end
    return win_start <= local < win_end


def next_window_start(window: DeployWindow, dt: datetime | None = None) -> datetime:
    """Return the nearest datetime when the window opens.

    If *dt* is already within the window, returns *dt* unchanged.
    """
    if dt is None:
        dt = datetime.now(UTC)

    if is_within_window(window, dt):
        return dt

    tz = ZoneInfo(window.timezone)
    local = dt.astimezone(tz)
    win_start, _ = _window_start_end(window, dt)

    local_mins = local.hour * 60 + local.minute
    start_mins = win_start.hour * 60 + win_start.minute
    end_h, end_m = map(int, window.end.split(":"))
    end_mins = end_h * 60 + end_m
    wraps = start_mins > end_mins

    if wraps or local_mins < start_mins:
        candidate_local = win_start
    else:
        candidate_local = win_start + timedelta(days=1)

    for _ in range(14):
        if candidate_local.isoweekday() in window.days:
            return candidate_local.astimezone(UTC)
        candidate_local += timedelta(days=1)

    return candidate_local.astimezone(UTC)


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
        known_hosts_path: Path to a known_hosts file. When set together
            with ``ssh_key``, GitPython performs strict host key
            verification instead of disabling it.
    """

    bind: str = "0.0.0.0:8000"
    work_dir: str = "/data/acme-git-webhook"
    ssh_key: str | None = None
    known_hosts_path: str | None = None


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
    deploy_window: DeployWindow | None = None


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
    deploy_window: DeployWindow | None = None


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
    deploy_window: DeployWindow | None = None


# Discriminated union so Pydantic selects the correct model based on
# the value of the ``provider`` field in the YAML configuration.
TargetConfig = Annotated[
    F5TargetConfig | IvantiTargetConfig | ExchangeTargetConfig,
    Field(discriminator="provider"),
]


DnsMethod = Literal["git", "nsupdate"]


class DnsUpdateConfig(BaseModel):
    """DNS update via nsupdate (RFC 2136)."""

    server: str = "127.0.0.1"
    port: int = 53
    key_name: str = "acme-key."
    key_file: str | None = None
    key_secret: str | None = None
    key_algorithm: str = "hmac-sha256"
    zone: str | None = None
    ttl: int = 60


class DnsConfig(BaseModel):
    nameservers: list[str] = ["8.8.8.8", "1.1.1.1"]
    timeout: int = 120
    poll_interval: int = 5
    wait_for_propagation: bool = False
    method: DnsMethod = "git"
    update: DnsUpdateConfig | None = None


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
    deploy_window: DeployWindow | None = None


class AppConfig(BaseModel):
    """Top-level application configuration.

    Groups authentication, webhook server, repository and Vault
    settings into a single validated object loaded from config.yaml.
    """

    auth: AuthConfig
    webhook: WebhookConfig
    repo: RepoConfig
    vault: VaultConfig | None = None
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
        logger.warning("Vault TLS verification is DISABLED (verify=False) — this is insecure and should only be used for development")
    return cfg
