import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fasteners import InterProcessLock
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

logger = logging.getLogger(__name__)

from app.auth import verify_api_key
from app.cert_monitor import CertMonitor
from app.config import AppConfig, F5TargetConfig, load_config
from app.dns_probe import check_propagation, validate_nameserver
from app.git_handler import clone_or_pull, commit_and_push
from app.models import AcmeRequest, CertDeployRequest, DeployRequest, PropagationRequest, RenewRequest
from app.targets.manager import DeployManager
from app.vault_handler import VaultHandler
from app.zone_handler import add_txt_record, remove_txt_record

# Module-level globals, populated once at startup via the lifespan hook.
config: AppConfig | None = None
vault_handler: VaultHandler | None = None
deploy_manager: DeployManager | None = None
cert_monitor: CertMonitor | None = None

# Reusable FastAPI security scheme that extracts the Bearer token from
# the Authorization header. It is shared by all protected endpoints.
security = HTTPBearer()

# Rate limiter keyed by client IP. The middleware enforces the default
# limit on every endpoint, including health. Use a reverse proxy for
# stricter per-client enforcement.
limiter = Limiter(key_func=get_remote_address, default_limits=["30/minute"])


def _rate_limit_exceeded_handler(request: Request, exc: Exception):
    """Return a 429 JSON response when the rate limit is exceeded."""
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": "Rate limit exceeded, try again later"},
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load the YAML configuration and initialise handlers.

    FastAPI calls the lifespan context manager on startup (before any
    request is accepted) and on shutdown. The config path is read from
    the CONFIG_PATH environment variable, defaulting to "config.yaml"
    relative to the working directory.
    """
    global config, vault_handler, deploy_manager, cert_monitor
    config_path = os.getenv("CONFIG_PATH", "config.yaml")
    config = load_config(config_path)
    env_key = os.environ.get("ACME_WEBHOOK_API_KEY")
    if env_key and config.auth:
        config.auth.api_keys.append(env_key)
    if config.vault and not config.vault.skip:
        vault_handler = VaultHandler(config.vault)

    # Build the target list: merge explicit ``targets`` with any
    # legacy ``f5`` section so existing configs keep working.
    target_configs: list = []
    if config.targets:
        target_configs.extend(config.targets)
    if config.f5:
        for i, host in enumerate(config.f5.hosts):
            target_configs.append(
                F5TargetConfig(
                    name=host.name or f"f5-{i}",
                    addr=host.addr,
                    username=host.username,
                    password_path=host.password_path,
                    verify=host.verify,
                    timeout=30,
                )
            )
    if target_configs:
        deploy_manager = DeployManager(target_configs)

    if config.monitor:
        cert_monitor = CertMonitor(config.monitor, vault_handler, openssl=config.openssl)
        cert_monitor.start()
    yield
    if cert_monitor is not None:
        cert_monitor.stop()
    if deploy_manager is not None:
        deploy_manager.close()


app = FastAPI(title="acme-git-webhook", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)


def _get_config() -> AppConfig:
    """Return the global config, raising an error if not yet loaded.

    This is a safety guard: if the lifespan hook failed to run or an
    endpoint is somehow called before startup, the 500 response will
    make the misconfiguration immediately visible instead of failing
    with a cryptic AttributeError later.

    Returns:
        The AppConfig instance loaded at startup.

    Raises:
        HTTPException 500: If the config was not loaded.
    """
    if config is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Config not loaded",
        )
    return config


def _auth_dep(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """FastAPI dependency that validates the Bearer token against the config.

    Wraps the low-level verify_api_key function with access to the
    application configuration so that routes do not need to pass the
    valid key list manually. Usage::

        @app.post("/acme/auth")
        def endpoint(..., _token: str = Depends(_auth_dep)): ...

    Args:
        credentials: Automatically extracted by HTTPBearer.

    Returns:
        The validated token string on success.

    Raises:
        HTTPException 401: If the token is not recognised.
    """
    cfg = _get_config()
    return verify_api_key(credentials, valid_keys=cfg.auth.api_keys)


def _repo_dir() -> Path:
    """Resolve the local working directory used for Git operations.

    Returns:
        Absolute, resolved Path to the work_dir from the config.
    """
    return Path(_get_config().webhook.work_dir).resolve()


def _lock_path() -> Path:
    """Path to the inter-process lock file.

    The lock prevents concurrent requests from operating on the same
    Git clone simultaneously, which would cause push conflicts or
    race conditions during commit.

    Returns:
        Path to ``repo.lock`` inside the work directory.
    """
    work_dir = _repo_dir()
    return work_dir / "repo.lock"


def _zone_name(domain: str) -> str:
    """Strip the ``_acme-challenge.`` and ``*.`` prefix from a domain.

    Example::

        _acme-challenge.example.com  ->  example.com
        _acme-challenge.*.example.com ->  *.example.com  (kept)

    Args:
        domain: The raw domain string as received from the ACME client.

    Returns:
        The bare zone name (without the ACME challenge prefix).
    """
    return domain.removeprefix("_acme-challenge.").removeprefix("*.")


@app.get("/certs/status")
def certs_status(
    _token: str = Depends(_auth_dep),
):
    """Return the latest certificate expiration status.

    Returns the cached result of the last certificate monitor check.
    If the monitor is not configured, returns an empty list.
    """
    monitor = cert_monitor
    if monitor is None:
        return {"certs": [], "detail": "Monitoring not configured"}
    return {"certs": monitor.get_status()}


@app.post("/acme/renew")
def acme_renew(
    req: RenewRequest,
    _token: str = Depends(_auth_dep),
):
    """Trigger immediate certificate renewal for a domain.

    Executes the configured ``renew_command`` with ``{domain}`` replaced
    by the request domain. The command (e.g. ``certbot renew``) is
    expected to call back the webhook endpoints for the DNS-01 challenge
    and finally ``/acme/deploy`` to store the new certificate.

    Returns 400 if no renewal command is configured.
    """
    monitor = cert_monitor
    if not monitor or not monitor.config or not monitor.config.renew_command:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Renewal not configured (monitor.renew_command)",
        )
    monitor._run_renew(req.domain)
    return {"status": "ok", "domain": req.domain}


@app.get("/health")
def health():
    """Simple healthcheck endpoint.

    Returns a 200 OK immediately. Does not verify that Git operations
    or the DNS infrastructure are functional — only that the webhook
    process is alive and accepting requests.
    """
    return {"status": "ok"}


@app.post("/acme/auth")
def acme_auth(
    req: AcmeRequest,
    _token: str = Depends(_auth_dep),
):
    """Handle the authentication phase of an ACME DNS-01 challenge.

    1. Acquires an inter-process file lock to serialise operations.
    2. Clones or pulls the latest version of the zone repository.
    3. Locates the correct Bind zone file for the requested domain.
    4. Inserts or replaces the ``_acme-challenge.<domain>`` TXT record.
    5. Stages, commits and pushes the change to the remote.

    The ACME client is expected to call this endpoint first, wait for
    DNS propagation (typically 60–120s), and then instruct the CA to
    validate the record.

    Args:
        req: JSON body containing ``domain`` and ``validation`` fields.
        _token: The validated API key (injected by the auth dependency).

    Returns:
        A JSON object with the operation status, domain and zone file
        name.

    Raises:
        HTTPException 423: If another ACME operation is currently in
            progress (lock held).
        HTTPException 500: If the config or zone file is missing.
    """
    cfg = _get_config()
    work_dir = _repo_dir()
    repo_root = work_dir / "zone-repo"
    lock_path = _lock_path()

    work_dir.mkdir(parents=True, exist_ok=True)

    # Acquire a file lock with a 30-second timeout. If the lock is held
    # by another concurrent request (from a different ACME renewal for
    # instance), this call blocks up to 30 seconds. If the lock is never
    # released during that window, we return 423 so the ACME client can
    # retry rather than hanging indefinitely.
    lock = InterProcessLock(str(lock_path))
    acquired = lock.acquire(blocking=True, timeout=30)
    if not acquired:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Another operation is in progress, try again",
        )
    try:
        # Step 1: ensure the local clone is up to date.
        clone_or_pull(work_dir, cfg.repo.url, cfg.repo.branch)

        # Step 2: inject the ACME challenge TXT record into the zone.
        add_txt_record(
            repo_root,
            req.domain,
            req.validation or "",
            cfg.repo.zone_path,
            cfg.repo.zone_file_suffix,
        )

        # Step 3: commit and push to the remote repository.
        # The CI/CD pipeline will detect the push and deploy the
        # updated zone to the authoritative DNS servers.
        commit_and_push(work_dir, f"ACME: add challenge for {req.domain}")
    finally:
        # Ensure the lock is always released, even if one of the
        # operations above raised an exception. This prevents the
        # webhook from deadlocking on subsequent requests.
        lock.release()

    result = {
        "status": "ok",
        "domain": req.domain,
        "zone_file": f"{_zone_name(req.domain)}{cfg.repo.zone_file_suffix}",
    }

    dns_cfg = cfg.dns
    if dns_cfg and dns_cfg.wait_for_propagation and req.validation:
        nameservers = [ns for ns in dns_cfg.nameservers if validate_nameserver(ns)]
        if not nameservers:
            nameservers = ["8.8.8.8", "1.1.1.1"]
        prop_result = check_propagation(
            req.domain,
            req.validation,
            nameservers,
            timeout=dns_cfg.timeout,
            poll_interval=dns_cfg.poll_interval,
        )
        result["propagation"] = "propagated" if not prop_result["pending"] else "timeout"
        result["propagation_matched"] = prop_result["matched"]
        result["propagation_pending"] = prop_result["pending"]
        result["propagation_elapsed"] = prop_result["elapsed"]

    return result


@app.post("/acme/cleanup")
def acme_cleanup(
    req: AcmeRequest,
    _token: str = Depends(_auth_dep),
):
    """Remove the ACME challenge TXT record after successful validation.

    This is the cleanup counterpart of ``acme_auth``. It follows the
    same lock / clone / modify / push pattern, but deletes the TXT
    record instead of adding one.

    The endpoint is idempotent: calling it twice for the same domain,
    or for a domain whose TXT record was never created, returns a
    200 with ``status: "skipped"`` rather than an error.

    Args:
        req: JSON body containing the ``domain`` field.
        _token: The validated API key (injected by the auth dependency).

    Returns:
        A JSON object indicating whether the record was removed or
        skipped.
    """
    cfg = _get_config()
    work_dir = _repo_dir()
    repo_root = work_dir / "zone-repo"
    lock_path = _lock_path()

    work_dir.mkdir(parents=True, exist_ok=True)

    # Same locking logic as acme_auth — see that method for details.
    lock = InterProcessLock(str(lock_path))
    acquired = lock.acquire(blocking=True, timeout=30)
    if not acquired:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Another operation is in progress, try again",
        )
    try:
        clone_or_pull(work_dir, cfg.repo.url, cfg.repo.branch)
        removed = remove_txt_record(
            repo_root,
            req.domain,
            cfg.repo.zone_path,
            cfg.repo.zone_file_suffix,
        )
        if removed:
            # Only commit and push if a record was actually deleted.
            # This avoids pushing an empty commit when cleanup is
            # called for a domain that had no challenge record.
            commit_and_push(work_dir, f"ACME: remove challenge for {req.domain}")
            return {
                "status": "ok",
                "domain": req.domain,
                "zone_file": Path(removed).name,
            }
        else:
            # No zone file or no TXT record — nothing to clean up.
            return {
                "status": "skipped",
                "domain": req.domain,
                "detail": "No TXT record found to remove",
            }
    finally:
        lock.release()


@app.post("/acme/wait-for-propagation")
def acme_wait_for_propagation(
    req: PropagationRequest,
    _token: str = Depends(_auth_dep),
):
    """Poll configured nameservers until the TXT record is propagated.

    Called after ``/acme/auth`` to wait until the newly inserted TXT
    record is visible on all DNS resolvers. The ACME client should
    call this endpoint before asking the CA to validate.

    The endpoint polls every ``poll_interval`` seconds (default: 5)
    until either every nameserver returns the expected validation token
    or the ``timeout`` (default: 120) is reached.

    Nameserver addresses are validated to reject private, loopback,
    and multicast IPs as a defence against SSRF and DNS amplification
    attacks. Invalid entries are silently dropped and replaced with
    safe defaults.

    Args:
        req: JSON body containing ``domain``, ``validation``,
            optional ``nameservers``, ``timeout`` and ``poll_interval``.
        _token: The validated API key (injected by the auth dependency).

    Returns:
        A JSON object with:
            - ``status``: ``"propagated"`` or ``"timeout"``.
            - ``matched``: list of nameservers that matched.
            - ``pending``: list of nameservers that never matched.
            - ``elapsed``: seconds elapsed.
    """
    cfg = _get_config()
    dns_cfg = cfg.dns
    default_ns = dns_cfg.nameservers if dns_cfg else ["8.8.8.8", "1.1.1.1"]
    nameservers = req.nameservers or default_ns
    nameservers = [ns for ns in nameservers if validate_nameserver(ns)]
    if not nameservers:
        nameservers = default_ns
    timeout = req.timeout if req.timeout is not None else (dns_cfg.timeout if dns_cfg else 120)
    poll_interval = req.poll_interval if req.poll_interval is not None else (dns_cfg.poll_interval if dns_cfg else 5)
    result = check_propagation(
        req.domain,
        req.validation,
        nameservers,
        timeout=timeout,
        poll_interval=poll_interval,
    )
    status = "propagated" if not result["pending"] else "timeout"
    return {
        "status": status,
        "domain": req.domain,
        "elapsed": result["elapsed"],
        "matched": result["matched"],
        "pending": result["pending"],
    }


@app.post("/acme/deploy")
def acme_deploy(
    req: CertDeployRequest,
    _token: str = Depends(_auth_dep),
):
    """Store a successfully-issued certificate in Vault.

    Called by the certbot deploy-hook after a successful renewal.
    The endpoint receives the PEM-encoded certificate, chain, and
    private key, then writes them to HashiCorp Vault's KV store for
    secure distribution.

    The private key is excluded from all log output — the request
    body is logged at DEBUG level with ``exclude={"privkey_pem"}``.

    If Vault is not configured (``vault: null`` in config.yaml) or
    ``skip: true``, the endpoint returns a 200 with
    ``status: "skipped"`` so that the certbot deploy-hook does not
    fail in development environments.

    Args:
        req: JSON body containing the PEM certificate material.
        _token: The validated API key (injected by the auth dependency).

    Returns:
        A JSON object with the operation status and vault path.

    Raises:
        HTTPException 502: If the Vault write operation fails.
    """
    cfg = _get_config()

    # Log the non-sensitive fields for debugging and audit.
    logger.debug("Certificate deploy request: %s", req.model_dump())

    if not cfg.vault or cfg.vault.skip:
        logger.info(
            "Vault is disabled or not configured, skipping deploy for %s",
            req.domain,
        )
        return {
            "status": "skipped",
            "domain": req.domain,
            "detail": "Vault not configured or skip=true",
        }

    handler = vault_handler
    if handler is None:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Vault handler not initialised",
        )

    try:
        vault_path = handler.store_cert(
            domain=req.domain,
            cert_pem=req.cert_pem,
            chain_pem=req.chain_pem,
            fullchain_pem=req.fullchain_pem,
            privkey_pem=req.privkey_pem,
        )
    except Exception as e:
        logger.error("Failed to store certificate in Vault: %s", e)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Vault operation failed",
        )

    return {
        "status": "ok",
        "domain": req.domain,
        "vault_path": vault_path,
    }


@app.get("/targets")
def list_targets(
    _token: str = Depends(_auth_dep),
):
    """List all configured deployment targets and their providers."""
    mgr = deploy_manager
    if mgr is None:
        return {"targets": []}
    return {"targets": [{"name": name, "provider": t.provider_type} for name, t in mgr.targets.items()]}


@app.post("/deploy/{domain}")
def deploy_cert_to_targets(
    domain: str,
    req: DeployRequest,
    _token: str = Depends(_auth_dep),
):
    """Deploy an existing Vault-stored certificate to one or more targets.

    If ``fullchain_pem`` and ``privkey_pem`` are provided in the request
    body they are used directly; otherwise the endpoint tries to read the
    certificate from Vault.

    When ``target_names`` is *None* or empty, the certificate is
    deployed to every registered target.
    """
    mgr = deploy_manager
    if mgr is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No deployment targets configured",
        )

    fullchain_pem = req.fullchain_pem
    privkey_pem = req.privkey_pem

    # Fall back to reading from Vault when PEMs are not provided.
    if fullchain_pem is None or privkey_pem is None:
        handler = vault_handler
        if handler is None:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Vault handler not available, provide PEMs explicitly",
            )
        try:
            if handler._client is None:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Vault client not initialized",
                )
            secret = handler._client.secrets.kv.v2.read_secret_version(
                mount_point=handler.config.kv_mount,
                path=f"{handler.config.certs_path}/{domain}",
            )
            data = secret.get("data", {}).get("data", {})
            fullchain_pem = data.get("fullchain.pem", "")
            privkey_pem = data.get("privkey.pem", "")
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to read certificate from Vault: {e}",
            )

    results = mgr.deploy(
        domain=domain,
        fullchain_pem=fullchain_pem,
        privkey_pem=privkey_pem,
        target_names=req.target_names,
    )

    return {
        "status": "ok",
        "domain": domain,
        "results": [r.model_dump() for r in results],
    }


@app.post("/deploy/{domain}/{target}")
def deploy_cert_to_single_target(
    domain: str,
    target: str,
    req: DeployRequest,
    _token: str = Depends(_auth_dep),
):
    """Deploy a certificate to a single named target.

    Convenience shortcut around ``POST /deploy/{domain}`` with
    ``target_names`` already set in the URL.
    """
    req.target_names = [target]
    return deploy_cert_to_targets(domain, req, _token)
