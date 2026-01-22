"""
Zero Trust Platform - Main Application Entry Point

AI-Powered Security Infrastructure with:
- Threat Intelligence RAG
- Policy Engine
- Risk Assessment
- Anomaly Detection
"""

import sys
from contextlib import asynccontextmanager
from typing import Any

import structlog
import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from zero_trust import __version__
from zero_trust.api.middleware import RequestLoggingMiddleware, SecurityHeadersMiddleware
from zero_trust.api.routes import api_router
from zero_trust.config import Settings, get_settings
from zero_trust.core.exceptions import ZeroTrustError

# Configure structured logging
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer() if get_settings().is_development else structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(
        structlog.stdlib.LEVEL_NAME_TO_LEVEL[get_settings().log_level.lower()]
    ),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.

    Handles startup and shutdown events for resource initialization.
    """
    settings = get_settings()

    # Startup
    await logger.ainfo(
        "application_starting",
        version=__version__,
        environment=settings.app_env,
    )

    # Validate production settings
    if settings.is_production:
        issues = settings.validate_production_settings()
        if issues:
            for issue in issues:
                await logger.aerror("configuration_issue", issue=issue)
            # In production, fail fast on configuration issues
            raise RuntimeError(f"Configuration issues: {', '.join(issues)}")

    # TODO: Initialize database connection pool
    # TODO: Initialize vector store client
    # TODO: Initialize LLM client

    await logger.ainfo("application_started", version=__version__)

    yield

    # Shutdown
    await logger.ainfo("application_shutting_down")

    # TODO: Close database connections
    # TODO: Close vector store client

    await logger.ainfo("application_stopped")


def create_app(settings: Settings | None = None) -> FastAPI:
    """
    Create and configure the FastAPI application.

    Args:
        settings: Optional settings override (useful for testing)

    Returns:
        Configured FastAPI application instance
    """
    settings = settings or get_settings()

    app = FastAPI(
        title="Zero Trust Platform",
        description="AI-Powered Security Infrastructure",
        version=__version__,
        docs_url="/docs" if settings.is_development else None,
        redoc_url="/redoc" if settings.is_development else None,
        openapi_url="/openapi.json" if settings.is_development else None,
        lifespan=lifespan,
    )

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.security.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add custom middleware (order matters - last added is first executed)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)

    # Register exception handlers
    @app.exception_handler(ZeroTrustError)
    async def zero_trust_error_handler(
        request: Request,
        exc: ZeroTrustError,
    ) -> JSONResponse:
        """Handle ZeroTrust-specific exceptions."""
        # Log the error with context (context is not exposed to client)
        await logger.awarning(
            "zero_trust_error",
            error_code=exc.code,
            error_message=exc.message,
            context=exc.context,
            path=request.url.path,
        )

        # Map error codes to HTTP status codes
        status_codes = {
            "AUTHENTICATION_ERROR": 401,
            "AUTHORIZATION_ERROR": 403,
            "VALIDATION_ERROR": 400,
            "POLICY_VIOLATION": 403,
            "THREAT_DETECTED": 403,
            "RATE_LIMIT_EXCEEDED": 429,
            "CONFIGURATION_ERROR": 500,
            "VECTOR_STORE_ERROR": 503,
            "LLM_ERROR": 503,
        }

        return JSONResponse(
            status_code=status_codes.get(exc.code, 500),
            content=exc.to_dict(),
        )

    @app.exception_handler(Exception)
    async def general_exception_handler(
        request: Request,
        exc: Exception,
    ) -> JSONResponse:
        """Handle unexpected exceptions."""
        await logger.aerror(
            "unhandled_exception",
            error=str(exc),
            error_type=type(exc).__name__,
            path=request.url.path,
        )

        # Don't expose internal errors in production
        if settings.is_production:
            return JSONResponse(
                status_code=500,
                content={"error": "INTERNAL_ERROR", "message": "An unexpected error occurred"},
            )

        return JSONResponse(
            status_code=500,
            content={
                "error": "INTERNAL_ERROR",
                "message": str(exc),
                "type": type(exc).__name__,
            },
        )

    # Include API routes
    app.include_router(api_router, prefix="/api/v1")

    return app


# Create the application instance
app = create_app()


def run() -> None:
    """Run the application using uvicorn."""
    settings = get_settings()

    uvicorn.run(
        "zero_trust.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.api_reload,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    run()
