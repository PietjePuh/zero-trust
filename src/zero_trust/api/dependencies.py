"""
FastAPI dependency injection providers.

Provides reusable dependencies for routes including authentication,
database sessions, and service instances.
"""

from typing import Annotated

from fastapi import Depends, Header, HTTPException, status

from zero_trust.config import Settings, get_settings
from zero_trust.core.exceptions import AuthenticationError
from zero_trust.core.security import decode_access_token


def get_current_settings() -> Settings:
    """Dependency to get application settings."""
    return get_settings()


SettingsDep = Annotated[Settings, Depends(get_current_settings)]


async def get_token_from_header(
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    """
    Extract JWT token from Authorization header.

    Expects format: "Bearer <token>"
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return parts[1]


async def get_current_user(
    token: Annotated[str, Depends(get_token_from_header)],
    settings: SettingsDep,
) -> dict:
    """
    Validate token and return current user info.

    Returns decoded token payload with user information.
    """
    try:
        payload = decode_access_token(token, settings)
        return payload
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.message,
            headers={"WWW-Authenticate": "Bearer"},
        ) from e


CurrentUser = Annotated[dict, Depends(get_current_user)]


async def require_admin(current_user: CurrentUser) -> dict:
    """
    Dependency that requires the current user to have admin role.
    """
    roles = current_user.get("roles", [])
    if "admin" not in roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


AdminUser = Annotated[dict, Depends(require_admin)]
