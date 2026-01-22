"""
Security utilities for authentication and authorization.

Implements JWT token handling, password hashing, and security helpers.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext

from zero_trust.config import Settings, get_settings
from zero_trust.core.exceptions import AuthenticationError

# Password hashing context using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """
    Hash a password using bcrypt.

    Args:
        password: Plain text password

    Returns:
        Hashed password string
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.

    Args:
        plain_password: Plain text password to verify
        hashed_password: Stored hashed password

    Returns:
        True if password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(
    subject: str,
    claims: dict[str, Any] | None = None,
    expires_delta: timedelta | None = None,
    settings: Settings | None = None,
) -> str:
    """
    Create a JWT access token.

    Args:
        subject: Token subject (typically user ID)
        claims: Additional claims to include in the token
        expires_delta: Token expiration time (defaults to settings)
        settings: Application settings (defaults to global settings)

    Returns:
        Encoded JWT token string
    """
    settings = settings or get_settings()

    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.security.jwt_expiration_minutes)

    expire = datetime.now(UTC) + expires_delta

    to_encode: dict[str, Any] = {
        "sub": subject,
        "exp": expire,
        "iat": datetime.now(UTC),
        "type": "access",
    }

    if claims:
        to_encode.update(claims)

    return jwt.encode(
        to_encode,
        settings.security.secret_key.get_secret_value(),
        algorithm=settings.security.jwt_algorithm,
    )


def decode_access_token(
    token: str,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """
    Decode and validate a JWT access token.

    Args:
        token: JWT token string
        settings: Application settings (defaults to global settings)

    Returns:
        Decoded token payload

    Raises:
        AuthenticationError: If token is invalid or expired
    """
    settings = settings or get_settings()

    try:
        payload = jwt.decode(
            token,
            settings.security.secret_key.get_secret_value(),
            algorithms=[settings.security.jwt_algorithm],
        )

        if payload.get("type") != "access":
            raise AuthenticationError(
                "Invalid token type",
                context={"expected": "access", "got": payload.get("type")},
            )

        return payload

    except JWTError as e:
        raise AuthenticationError(
            "Invalid or expired token",
            context={"error": str(e)},
        ) from e


def create_refresh_token(
    subject: str,
    settings: Settings | None = None,
) -> str:
    """
    Create a JWT refresh token with longer expiration.

    Args:
        subject: Token subject (typically user ID)
        settings: Application settings

    Returns:
        Encoded JWT refresh token
    """
    settings = settings or get_settings()

    # Refresh tokens last 7 days
    expires_delta = timedelta(days=7)
    expire = datetime.now(UTC) + expires_delta

    to_encode = {
        "sub": subject,
        "exp": expire,
        "iat": datetime.now(UTC),
        "type": "refresh",
    }

    return jwt.encode(
        to_encode,
        settings.security.secret_key.get_secret_value(),
        algorithm=settings.security.jwt_algorithm,
    )


def decode_refresh_token(
    token: str,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """
    Decode and validate a JWT refresh token.

    Args:
        token: JWT refresh token string
        settings: Application settings

    Returns:
        Decoded token payload

    Raises:
        AuthenticationError: If token is invalid or expired
    """
    settings = settings or get_settings()

    try:
        payload = jwt.decode(
            token,
            settings.security.secret_key.get_secret_value(),
            algorithms=[settings.security.jwt_algorithm],
        )

        if payload.get("type") != "refresh":
            raise AuthenticationError(
                "Invalid token type",
                context={"expected": "refresh", "got": payload.get("type")},
            )

        return payload

    except JWTError as e:
        raise AuthenticationError(
            "Invalid or expired refresh token",
            context={"error": str(e)},
        ) from e


def generate_request_id() -> str:
    """
    Generate a unique request ID for tracing.

    Returns:
        Unique request identifier
    """
    import uuid

    return str(uuid.uuid4())
