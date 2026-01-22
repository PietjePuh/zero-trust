"""
Custom exceptions for the Zero Trust platform.

All exceptions inherit from ZeroTrustError for consistent handling.
Each exception includes context for audit logging and debugging.
"""

from typing import Any


class ZeroTrustError(Exception):
    """
    Base exception for all Zero Trust platform errors.

    Attributes:
        message: Human-readable error description
        code: Machine-readable error code for API responses
        context: Additional context for logging/debugging (never exposed to clients)
    """

    def __init__(
        self,
        message: str,
        code: str = "ZERO_TRUST_ERROR",
        context: dict[str, Any] | None = None,
    ) -> None:
        self.message = message
        self.code = code
        self.context = context or {}
        super().__init__(self.message)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API response (excludes sensitive context)."""
        return {
            "error": self.code,
            "message": self.message,
        }


class AuthenticationError(ZeroTrustError):
    """Raised when authentication fails."""

    def __init__(
        self,
        message: str = "Authentication failed",
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, code="AUTHENTICATION_ERROR", context=context)


class AuthorizationError(ZeroTrustError):
    """Raised when authorization check fails."""

    def __init__(
        self,
        message: str = "Access denied",
        resource: str | None = None,
        action: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        ctx = context or {}
        if resource:
            ctx["resource"] = resource
        if action:
            ctx["action"] = action
        super().__init__(message, code="AUTHORIZATION_ERROR", context=ctx)


class ValidationError(ZeroTrustError):
    """Raised when input validation fails."""

    def __init__(
        self,
        message: str = "Validation failed",
        field: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        ctx = context or {}
        if field:
            ctx["field"] = field
        super().__init__(message, code="VALIDATION_ERROR", context=ctx)


class PolicyViolationError(ZeroTrustError):
    """Raised when a security policy is violated."""

    def __init__(
        self,
        message: str = "Policy violation detected",
        policy_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        ctx = context or {}
        if policy_id:
            ctx["policy_id"] = policy_id
        super().__init__(message, code="POLICY_VIOLATION", context=ctx)


class ThreatDetectedError(ZeroTrustError):
    """Raised when a security threat is detected."""

    def __init__(
        self,
        message: str = "Potential threat detected",
        threat_type: str | None = None,
        severity: str = "medium",
        context: dict[str, Any] | None = None,
    ) -> None:
        ctx = context or {}
        ctx["threat_type"] = threat_type
        ctx["severity"] = severity
        super().__init__(message, code="THREAT_DETECTED", context=ctx)


class RateLimitError(ZeroTrustError):
    """Raised when rate limit is exceeded."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: int | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        ctx = context or {}
        if retry_after:
            ctx["retry_after"] = retry_after
        super().__init__(message, code="RATE_LIMIT_EXCEEDED", context=ctx)


class ConfigurationError(ZeroTrustError):
    """Raised when there's a configuration problem."""

    def __init__(
        self,
        message: str = "Configuration error",
        setting: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        ctx = context or {}
        if setting:
            ctx["setting"] = setting
        super().__init__(message, code="CONFIGURATION_ERROR", context=ctx)


class VectorStoreError(ZeroTrustError):
    """Raised when vector store operations fail."""

    def __init__(
        self,
        message: str = "Vector store operation failed",
        operation: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        ctx = context or {}
        if operation:
            ctx["operation"] = operation
        super().__init__(message, code="VECTOR_STORE_ERROR", context=ctx)


class LLMError(ZeroTrustError):
    """Raised when LLM operations fail."""

    def __init__(
        self,
        message: str = "LLM operation failed",
        model: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        ctx = context or {}
        if model:
            ctx["model"] = model
        super().__init__(message, code="LLM_ERROR", context=ctx)
