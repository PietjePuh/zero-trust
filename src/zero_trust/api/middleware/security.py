"""
Security middleware for HTTP headers and request validation.

Implements security headers, request validation, and basic protection.
"""

import time
from collections.abc import Callable
from typing import Any

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from zero_trust.core.security import generate_request_id


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware that adds security headers to all responses.

    Implements OWASP recommended security headers.
    """

    def __init__(
        self,
        app: ASGIApp,
        content_security_policy: str | None = None,
    ) -> None:
        super().__init__(app)
        self.csp = content_security_policy or "default-src 'self'"

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Any],
    ) -> Response:
        # Generate request ID for tracing
        request_id = generate_request_id()
        request.state.request_id = request_id

        # Record start time
        start_time = time.perf_counter()

        # Process request
        response: Response = await call_next(request)

        # Calculate processing time
        process_time = time.perf_counter() - start_time

        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = self.csp
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), payment=(), usb=()"
        )

        # Add request tracking headers
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = f"{process_time:.4f}"

        # Prevent caching of sensitive responses
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            response.headers["Pragma"] = "no-cache"

        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Simple in-memory rate limiting middleware.

    For production, use Redis-backed rate limiting.
    """

    def __init__(
        self,
        app: ASGIApp,
        requests_per_minute: int = 60,
    ) -> None:
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.requests: dict[str, list[float]] = {}

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request."""
        # Check for forwarded header (behind proxy)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _is_rate_limited(self, client_ip: str) -> bool:
        """Check if client has exceeded rate limit."""
        now = time.time()
        window_start = now - 60  # 1 minute window

        # Clean up old entries
        if client_ip in self.requests:
            self.requests[client_ip] = [
                ts for ts in self.requests[client_ip] if ts > window_start
            ]
        else:
            self.requests[client_ip] = []

        # Check rate limit
        if len(self.requests[client_ip]) >= self.requests_per_minute:
            return True

        # Record this request
        self.requests[client_ip].append(now)
        return False

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Any],
    ) -> Response:
        client_ip = self._get_client_ip(request)

        if self._is_rate_limited(client_ip):
            return Response(
                content='{"error": "RATE_LIMIT_EXCEEDED", "message": "Too many requests"}',
                status_code=429,
                media_type="application/json",
                headers={"Retry-After": "60"},
            )

        return await call_next(request)
