"""API route modules."""

from fastapi import APIRouter

from zero_trust.api.routes import health, auth, policy, threat_intel, risk

# Main API router that aggregates all route modules
api_router = APIRouter()

# Include all route modules
api_router.include_router(health.router, tags=["Health"])
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(policy.router, prefix="/policy", tags=["Policy Engine"])
api_router.include_router(threat_intel.router, prefix="/threat-intel", tags=["Threat Intelligence"])
api_router.include_router(risk.router, prefix="/risk", tags=["Risk Assessment"])

__all__ = ["api_router"]
