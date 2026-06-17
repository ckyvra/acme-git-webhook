from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# Shared HTTPBearer dependency. FastAPI extracts and validates the
# Authorization: Bearer <token> header automatically. The raw credential
# string is then checked against the list of allowed API keys from the
# YAML configuration.
security = HTTPBearer()


def verify_api_key(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    valid_keys: list[str] | None = None,
) -> str:
    """Extract and validate the Bearer token from the incoming request.

    FastAPI injects the parsed Authorization header via the Depends on
    the HTTPBearer security scheme. The token is compared against the
    list of pre-configured valid keys. This function is meant to be
    used as a FastAPI dependency — any route that includes
    ``_token: str = Depends(_auth_dep)`` will reject unauthenticated
    requests automatically.

    Args:
        credentials: Automatically provided by FastAPI from the
            Authorization header.
        valid_keys: List of accepted API keys, typically loaded from
            config.auth.api_keys at startup.

    Returns:
        The raw token string on success.

    Raises:
        HTTPException 401: If the token is not in the valid_keys list.
        HTTPException 500: If valid_keys was not provided (misconfiguration).
    """
    if valid_keys is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Auth not configured",
        )
    if credentials.credentials not in valid_keys:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    return credentials.credentials
