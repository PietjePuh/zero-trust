"""
Request logging middleware with structured logging.

Provides audit trail for all API requests.
"""

import time
from collections.abc import Callable
from typing import Any

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = structlog.get_logger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware that logs all requests with structured data.

    Captures request/response metadata for audit and debugging.
    Sensitive data (auth headers, request bodies) are excluded.
    """

    def __init__(
        self,
        app: ASGIApp,
        exclude_paths: list[str] | None = None,
    ) -> None:
        super().__init__(app)
        self.exclude_paths = exclude_paths or ["/health", "/ready", "/metrics"]

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Any],
    ) -> Response:
        # Skip logging for excluded paths
        if request.url.path in self.exclude_paths:
            return await call_next(request)

        # Extract request metadata
        request_id = getattr(request.state, "request_id", "unknown")
        client_ip = self._get_client_ip(request)

        start_time = time.perf_counter()

        # Log request
        await logger.ainfo(
            "request_started",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            query=str(request.query_params),
            client_ip=client_ip,
            user_agent=request.headers.get("user-agent", "unknown"),
        )

        # Process request
        try:
            response: Response = await call_next(request)
            process_time = time.perf_counter() - start_time

            # Log response
            await logger.ainfo(
                "request_completed",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                process_time=f"{process_time:.4f}s",
                client_ip=client_ip,
            )

            return response

        except Exception as e:
            process_time = time.perf_counter() - start_time

            # Log error
            await logger.aerror(
                "request_failed",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                error=str(e),
                error_type=type(e).__name__,
                process_time=f"{process_time:.4f}s",
                client_ip=client_ip,
            )
            raise

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"
