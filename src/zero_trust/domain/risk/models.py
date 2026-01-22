"""
Risk Assessment domain models.

Defines the core data structures for risk scoring and assessment.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Risk level categories."""

    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskFactorType(str, Enum):
    """Types of risk factors."""

    AUTHENTICATION = "authentication"
    BEHAVIORAL = "behavioral"
    LOCATION = "location"
    DEVICE = "device"
    NETWORK = "network"
    RESOURCE = "resource"
    TEMPORAL = "temporal"
    THREAT_INTEL = "threat_intel"


class RiskFactor(BaseModel):
    """Individual risk factor contributing to overall score."""

    name: str
    type: RiskFactorType
    description: str
    score: float = Field(ge=0.0, le=1.0, description="Risk contribution (0=safe, 1=max risk)")
    weight: float = Field(ge=0.0, le=1.0, description="Importance weight")
    details: dict[str, Any] = Field(default_factory=dict)
    mitigations: list[str] = Field(default_factory=list)


class RiskContext(BaseModel):
    """Context for risk assessment."""

    entity_type: str = Field(description="Type of entity: user, device, request, session")
    entity_id: str
    user_id: str | None = None
    source_ip: str | None = None
    user_agent: str | None = None
    resource: str | None = None
    action: str | None = None
    device_info: dict[str, Any] = Field(default_factory=dict)
    session_info: dict[str, Any] = Field(default_factory=dict)
    additional_context: dict[str, Any] = Field(default_factory=dict)


class RiskAssessment(BaseModel):
    """Complete risk assessment result."""

    id: str
    timestamp: datetime
    context: RiskContext
    risk_score: float = Field(ge=0.0, le=1.0)
    risk_level: RiskLevel
    factors: list[RiskFactor]
    recommendations: list[str]
    requires_mfa: bool = False
    requires_verification: bool = False
    allow_action: bool = True
    explanation: str | None = None


class RiskThreshold(BaseModel):
    """Risk threshold configuration."""

    level: RiskLevel
    min_score: float = Field(ge=0.0, le=1.0)
    max_score: float = Field(ge=0.0, le=1.0)
    require_mfa: bool = False
    require_verification: bool = False
    block_action: bool = False


class RiskTrend(BaseModel):
    """Risk trend analysis for an entity."""

    entity_type: str
    entity_id: str
    current_score: float
    average_7d: float
    average_30d: float
    trend: str  # "increasing", "stable", "decreasing"
    peak_score: float
    peak_timestamp: datetime | None = None
