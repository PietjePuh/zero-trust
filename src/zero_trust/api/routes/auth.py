"""
Authentication endpoints.

Handles user authentication, token management, and session operations.
"""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

from zero_trust.api.dependencies import CurrentUser, SettingsDep
from zero_trust.core.security import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    hash_password,
    verify_password,
)

router = APIRouter()


# Request/Response Models
class LoginRequest(BaseModel):
    """Login request payload."""

    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class TokenResponse(BaseModel):
    """Token response payload."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="Token expiration time in seconds")


class RefreshRequest(BaseModel):
    """Token refresh request."""

    refresh_token: str


class UserInfo(BaseModel):
    """Current user information."""

    user_id: str
    email: str | None = None
    roles: list[str] = []
    issued_at: datetime
    expires_at: datetime


class VerifyRequest(BaseModel):
    """Request to verify a session/token for zero-trust checks."""

    token: str
    resource: str = Field(description="Resource being accessed")
    action: str = Field(description="Action being performed")
    context: dict = Field(default_factory=dict, description="Additional context")


class VerifyResponse(BaseModel):
    """Zero-trust verification response."""

    allowed: bool
    reason: str | None = None
    risk_score: float = Field(ge=0.0, le=1.0)
    requires_mfa: bool = False
    policy_id: str | None = None


# Temporary in-memory user store (replace with database)
_temp_users: dict[str, dict] = {
    "admin@example.com": {
        "id": "user_001",
        "email": "admin@example.com",
        "password_hash": hash_password("admin123456"),
        "roles": ["admin", "user"],
    }
}


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate user",
    description="Authenticate with email and password to receive access tokens.",
)
async def login(request: LoginRequest, settings: SettingsDep) -> TokenResponse:
    """
    Authenticate user and return JWT tokens.

    Validates credentials and issues access + refresh tokens.
    """
    # Look up user (replace with database query)
    user = _temp_users.get(request.email)

    if not user or not verify_password(request.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create tokens
    access_token = create_access_token(
        subject=user["id"],
        claims={"email": user["email"], "roles": user["roles"]},
        settings=settings,
    )
    refresh_token = create_refresh_token(subject=user["id"], settings=settings)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.security.jwt_expiration_minutes * 60,
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access token",
    description="Exchange a refresh token for a new access token.",
)
async def refresh_token(request: RefreshRequest, settings: SettingsDep) -> TokenResponse:
    """
    Refresh access token using refresh token.

    Validates the refresh token and issues a new access token.
    """
    try:
        payload = decode_refresh_token(request.refresh_token, settings)
        user_id = payload["sub"]

        # Look up user to get current roles (replace with database query)
        user = next((u for u in _temp_users.values() if u["id"] == user_id), None)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
            )

        # Create new access token
        access_token = create_access_token(
            subject=user_id,
            claims={"email": user["email"], "roles": user["roles"]},
            settings=settings,
        )

        # Optionally rotate refresh token
        new_refresh_token = create_refresh_token(subject=user_id, settings=settings)

        return TokenResponse(
            access_token=access_token,
            refresh_token=new_refresh_token,
            expires_in=settings.security.jwt_expiration_minutes * 60,
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        ) from e


@router.get(
    "/me",
    response_model=UserInfo,
    summary="Get current user",
    description="Get information about the currently authenticated user.",
)
async def get_current_user_info(current_user: CurrentUser) -> UserInfo:
    """
    Return information about the authenticated user.

    Extracts user info from the validated JWT token.
    """
    return UserInfo(
        user_id=current_user["sub"],
        email=current_user.get("email"),
        roles=current_user.get("roles", []),
        issued_at=datetime.fromtimestamp(current_user["iat"], tz=UTC),
        expires_at=datetime.fromtimestamp(current_user["exp"], tz=UTC),
    )


@router.post(
    "/verify",
    response_model=VerifyResponse,
    summary="Zero-trust verification",
    description="Verify if an action is allowed under zero-trust policies.",
)
async def verify_access(request: VerifyRequest, settings: SettingsDep) -> VerifyResponse:
    """
    Zero-trust verification endpoint.

    Evaluates whether a request should be allowed based on:
    - Token validity
    - Policy rules
    - Risk assessment
    - Contextual factors

    This is the core zero-trust decision point.
    """
    # TODO: Implement full zero-trust verification logic
    # For now, return a basic response based on token validity

    try:
        from zero_trust.core.security import decode_access_token

        payload = decode_access_token(request.token, settings)

        # Basic authorization check
        roles = payload.get("roles", [])

        # Simple policy: admin can do anything, users have limited access
        if "admin" in roles:
            return VerifyResponse(
                allowed=True,
                reason="Admin access granted",
                risk_score=0.1,
                policy_id="policy_admin_allow",
            )

        # For regular users, apply more restrictive policies
        read_actions = ["read", "view", "list", "get"]
        if request.action.lower() in read_actions:
            return VerifyResponse(
                allowed=True,
                reason="Read access granted",
                risk_score=0.2,
                policy_id="policy_user_read",
            )

        # Write actions require additional verification
        return VerifyResponse(
            allowed=False,
            reason="Write access requires elevated privileges",
            risk_score=0.6,
            requires_mfa=True,
            policy_id="policy_user_write_denied",
        )

    except Exception:
        return VerifyResponse(
            allowed=False,
            reason="Invalid or expired token",
            risk_score=1.0,
            policy_id="policy_invalid_token",
        )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Logout",
    description="Invalidate the current session.",
)
async def logout(current_user: CurrentUser) -> None:
    """
    Logout and invalidate tokens.

    In a full implementation, this would:
    - Add the token to a blocklist
    - Clear any session data
    - Emit audit event
    """
    # TODO: Implement token blocklist
    # For now, client-side token deletion is sufficient
    pass
