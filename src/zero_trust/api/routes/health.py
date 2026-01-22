"""
Health check endpoints for monitoring and orchestration.

Provides liveness and readiness probes for Kubernetes/container orchestration.
"""

from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Response
from pydantic import BaseModel, Field

from zero_trust import __version__
from zero_trust.api.dependencies import SettingsDep

router = APIRouter()


class HealthStatus(BaseModel):
    """Health check response model."""

    status: Literal["healthy", "degraded", "unhealthy"]
    version: str
    environment: str
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class ReadinessStatus(BaseModel):
    """Readiness check response with component status."""

    status: Literal["ready", "not_ready"]
    checks: dict[str, bool]
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class DetailedHealth(BaseModel):
    """Detailed health information for debugging."""

    status: Literal["healthy", "degraded", "unhealthy"]
    version: str
    environment: str
    components: dict[str, dict]
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


@router.get(
    "/health",
    response_model=HealthStatus,
    summary="Liveness probe",
    description="Basic health check for liveness probes. Returns 200 if the service is running.",
)
async def health_check(settings: SettingsDep) -> HealthStatus:
    """
    Basic liveness probe.

    Used by load balancers and orchestrators to verify the service is running.
    This endpoint should always return quickly and not depend on external services.
    """
    return HealthStatus(
        status="healthy",
        version=__version__,
        environment=settings.app_env,
    )


@router.get(
    "/ready",
    response_model=ReadinessStatus,
    summary="Readiness probe",
    description="Readiness check that verifies all dependencies are available.",
)
async def readiness_check(settings: SettingsDep, response: Response) -> ReadinessStatus:
    """
    Readiness probe that checks critical dependencies.

    Used by orchestrators to determine if the service can handle traffic.
    Checks database connectivity, vector store, and other critical services.
    """
    checks: dict[str, bool] = {}

    # Check configuration validity
    config_issues = settings.validate_production_settings()
    checks["configuration"] = len(config_issues) == 0 or not settings.is_production

    # TODO: Add actual health checks when infrastructure is connected
    # For now, stub out the checks
    checks["database"] = True  # Will check actual connection
    checks["vector_store"] = True  # Will check Weaviate connection
    checks["cache"] = True  # Will check Redis connection

    all_ready = all(checks.values())

    if not all_ready:
        response.status_code = 503

    return ReadinessStatus(
        status="ready" if all_ready else "not_ready",
        checks=checks,
    )


@router.get(
    "/health/detailed",
    response_model=DetailedHealth,
    summary="Detailed health check",
    description="Comprehensive health information including component status.",
)
async def detailed_health(settings: SettingsDep) -> DetailedHealth:
    """
    Detailed health check for debugging and monitoring.

    Returns comprehensive information about all system components.
    Should only be exposed to internal monitoring systems.
    """
    components: dict[str, dict] = {}

    # Application info
    components["application"] = {
        "status": "healthy",
        "version": __version__,
        "environment": settings.app_env,
        "debug": settings.debug,
    }

    # Database status (stub for now)
    components["database"] = {
        "status": "healthy",
        "type": "postgresql",
        "pool_size": settings.database.pool_size,
    }

    # Vector store status (stub for now)
    components["vector_store"] = {
        "status": "healthy",
        "type": "weaviate",
        "url": settings.weaviate.url,
    }

    # LLM status (stub for now)
    components["llm"] = {
        "status": "healthy" if settings.anthropic.api_key.get_secret_value() else "not_configured",
        "model": settings.anthropic.model,
    }

    # Determine overall status
    statuses = [c.get("status", "unknown") for c in components.values()]
    if all(s == "healthy" for s in statuses):
        overall_status = "healthy"
    elif any(s == "unhealthy" for s in statuses):
        overall_status = "unhealthy"
    else:
        overall_status = "degraded"

    return DetailedHealth(
        status=overall_status,  # type: ignore[arg-type]
        version=__version__,
        environment=settings.app_env,
        components=components,
    )
