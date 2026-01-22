"""
Policy Engine domain models.

Defines the core data structures for policy management and evaluation.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class PolicyEffect(str, Enum):
    """Policy effect - the action to take when policy matches."""

    ALLOW = "allow"
    DENY = "deny"


class ConditionOperator(str, Enum):
    """Operators for policy conditions."""

    EQUALS = "eq"
    NOT_EQUALS = "ne"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    MATCHES = "matches"  # Regex match
    GREATER_THAN = "gt"
    LESS_THAN = "lt"
    GREATER_OR_EQUAL = "gte"
    LESS_OR_EQUAL = "lte"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"


class PolicyCondition(BaseModel):
    """A condition that must be met for the policy to apply."""

    field: str = Field(description="Field path to evaluate (e.g., 'subject.role', 'context.ip')")
    operator: ConditionOperator
    value: Any = Field(description="Value to compare against")
    description: str | None = None


class Policy(BaseModel):
    """Security policy definition."""

    id: str
    name: str
    description: str = ""
    effect: PolicyEffect
    resources: list[str] = Field(description="Resource patterns this policy applies to")
    actions: list[str] = Field(description="Actions this policy governs")
    conditions: list[PolicyCondition] = Field(default_factory=list)
    priority: int = Field(default=0, ge=0, le=1000)
    enabled: bool = True
    created_at: datetime | None = None
    updated_at: datetime | None = None
    created_by: str | None = None
    tags: list[str] = []


class PolicyEvaluationContext(BaseModel):
    """Context for policy evaluation."""

    subject: dict[str, Any] = Field(description="The subject (user/service) making the request")
    resource: str = Field(description="The resource being accessed")
    action: str = Field(description="The action being performed")
    environment: dict[str, Any] = Field(
        default_factory=dict, description="Environmental context (time, ip, etc.)"
    )


class PolicyDecision(BaseModel):
    """Result of policy evaluation."""

    effect: PolicyEffect
    policy_id: str | None = Field(description="ID of the policy that made the decision")
    policy_name: str | None = None
    reason: str
    matching_policies: list[str] = Field(default_factory=list)
    evaluation_time_ms: float
    ai_explanation: str | None = None


class PolicySet(BaseModel):
    """A collection of related policies."""

    id: str
    name: str
    description: str = ""
    policies: list[Policy]
    combining_algorithm: str = "deny_overrides"  # deny_overrides, permit_overrides, first_applicable
    enabled: bool = True
