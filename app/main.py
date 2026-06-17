import os
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fasteners import InterProcessLock

from app.auth import verify_api_key
from app.config import AppConfig, load_config
from app.git_handler import clone_or_pull, commit_and_push
from app.models import AcmeRequest
from app.zone_handler import add_txt_record, remove_txt_record

# Module-level config, populated once at startup via the lifespan hook.
# Using a global is the simplest approach for a single-process uvicorn
# instance. For multi-worker deployments, the config should be loaded
# inside each worker's lifespan or passed via a dependency provider.
config: AppConfig | None = None

# Reusable FastAPI security scheme that extracts the Bearer token from
# the Authorization header. It is shared by all protected endpoints.
security = HTTPBearer()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load the YAML configuration once when the application starts.

    FastAPI calls the lifespan context manager on startup (before any
    request is accepted) and on shutdown. The config path is read from
    the CONFIG_PATH environment variable, defaulting to "config.yaml"
    relative to the working directory.
    """
    global config
    config_path = os.getenv("CONFIG_PATH", "config.yaml")
    config = load_config(config_path)
    yield


app = FastAPI(title="acme-git-webhook", lifespan=lifespan)


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

    # Acquire a blocking file lock. If the lock is held by another
    # concurrent request (from a different ACME renewal for instance),
    # this call blocks until the lock is released. The blocking=True
    # parameter means we wait — if the lock is never released, the
    # request will hang until the server timeout.
    lock = InterProcessLock(str(lock_path))
    acquired = lock.acquire(blocking=True)
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
            req.validation,
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

    return {
        "status": "ok",
        "domain": req.domain,
        "zone_file": f"{_zone_name(req.domain)}{cfg.repo.zone_file_suffix}",
    }


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
    acquired = lock.acquire(blocking=True)
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
