"""
Policy Engine API endpoints.

Manages security policies and provides policy evaluation.
Uses LLM-assisted reasoning for complex policy decisions.
"""

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from zero_trust.api.dependencies import AdminUser, CurrentUser, SettingsDep

router = APIRouter()


class PolicyEffect(str, Enum):
    """Policy effect - allow or deny."""

    ALLOW = "allow"
    DENY = "deny"


class PolicyCondition(BaseModel):
    """A condition that must be met for the policy to apply."""

    field: str = Field(description="Field to evaluate (e.g., 'user.role', 'request.ip')")
    operator: str = Field(description="Comparison operator (eq, ne, in, contains, matches)")
    value: Any = Field(description="Value to compare against")


class Policy(BaseModel):
    """Security policy definition."""

    id: str = Field(default_factory=lambda: f"policy_{uuid4().hex[:8]}")
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="")
    effect: PolicyEffect
    resources: list[str] = Field(description="Resources this policy applies to")
    actions: list[str] = Field(description="Actions this policy governs")
    conditions: list[PolicyCondition] = Field(default_factory=list)
    priority: int = Field(default=0, ge=0, le=1000, description="Higher priority = evaluated first")
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class PolicyCreateRequest(BaseModel):
    """Request to create a new policy."""

    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="")
    effect: PolicyEffect
    resources: list[str]
    actions: list[str]
    conditions: list[PolicyCondition] = Field(default_factory=list)
    priority: int = Field(default=0, ge=0, le=1000)


class PolicyEvaluationRequest(BaseModel):
    """Request to evaluate policies against a specific context."""

    subject: dict = Field(description="The subject (user/service) making the request")
    resource: str = Field(description="The resource being accessed")
    action: str = Field(description="The action being performed")
    context: dict = Field(default_factory=dict, description="Additional context")


class PolicyEvaluationResponse(BaseModel):
    """Result of policy evaluation."""

    decision: PolicyEffect
    matching_policies: list[str] = Field(description="IDs of policies that matched")
    reason: str
    evaluation_time_ms: float
    ai_reasoning: str | None = Field(default=None, description="LLM explanation if used")


class NaturalLanguagePolicyRequest(BaseModel):
    """Request to create a policy from natural language."""

    description: str = Field(
        min_length=10,
        description="Natural language description of the policy",
        examples=["Allow read access to reports for users in the finance team"],
    )


# Temporary in-memory policy store (replace with database)
_policies: dict[str, Policy] = {
    "policy_default_deny": Policy(
        id="policy_default_deny",
        name="Default Deny",
        description="Deny all access by default (zero trust)",
        effect=PolicyEffect.DENY,
        resources=["*"],
        actions=["*"],
        priority=0,
    ),
    "policy_admin_allow": Policy(
        id="policy_admin_allow",
        name="Admin Full Access",
        description="Allow admins full access to all resources",
        effect=PolicyEffect.ALLOW,
        resources=["*"],
        actions=["*"],
        conditions=[
            PolicyCondition(field="user.role", operator="in", value=["admin"]),
        ],
        priority=1000,
    ),
}


@router.get(
    "/",
    response_model=list[Policy],
    summary="List policies",
    description="Get all security policies.",
)
async def list_policies(current_user: CurrentUser) -> list[Policy]:
    """List all security policies."""
    return list(_policies.values())


@router.get(
    "/{policy_id}",
    response_model=Policy,
    summary="Get policy",
    description="Get a specific policy by ID.",
)
async def get_policy(policy_id: str, current_user: CurrentUser) -> Policy:
    """Get a specific policy by ID."""
    policy = _policies.get(policy_id)
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy {policy_id} not found",
        )
    return policy


@router.post(
    "/",
    response_model=Policy,
    status_code=status.HTTP_201_CREATED,
    summary="Create policy",
    description="Create a new security policy.",
)
async def create_policy(request: PolicyCreateRequest, admin_user: AdminUser) -> Policy:
    """Create a new security policy (admin only)."""
    policy = Policy(
        name=request.name,
        description=request.description,
        effect=request.effect,
        resources=request.resources,
        actions=request.actions,
        conditions=request.conditions,
        priority=request.priority,
    )
    _policies[policy.id] = policy
    return policy


@router.put(
    "/{policy_id}",
    response_model=Policy,
    summary="Update policy",
    description="Update an existing policy.",
)
async def update_policy(
    policy_id: str,
    request: PolicyCreateRequest,
    admin_user: AdminUser,
) -> Policy:
    """Update an existing policy (admin only)."""
    if policy_id not in _policies:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy {policy_id} not found",
        )

    policy = _policies[policy_id]
    policy.name = request.name
    policy.description = request.description
    policy.effect = request.effect
    policy.resources = request.resources
    policy.actions = request.actions
    policy.conditions = request.conditions
    policy.priority = request.priority
    policy.updated_at = datetime.now(UTC)

    return policy


@router.delete(
    "/{policy_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete policy",
    description="Delete a policy.",
)
async def delete_policy(policy_id: str, admin_user: AdminUser) -> None:
    """Delete a policy (admin only)."""
    if policy_id not in _policies:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy {policy_id} not found",
        )
    del _policies[policy_id]


@router.post(
    "/evaluate",
    response_model=PolicyEvaluationResponse,
    summary="Evaluate policies",
    description="Evaluate all policies against a given context.",
)
async def evaluate_policies(
    request: PolicyEvaluationRequest,
    settings: SettingsDep,
) -> PolicyEvaluationResponse:
    """
    Evaluate policies for a specific request context.

    This is the Policy Decision Point (PDP) - the core of the policy engine.
    Evaluates all applicable policies and returns a decision.
    """
    import time

    start = time.perf_counter()

    # Get policies sorted by priority (highest first)
    sorted_policies = sorted(_policies.values(), key=lambda p: p.priority, reverse=True)

    matching_policies: list[str] = []
    decision = PolicyEffect.DENY
    reason = "No matching policy found (default deny)"

    for policy in sorted_policies:
        if not policy.enabled:
            continue

        # Check if policy applies to this resource and action
        resource_match = any(
            _matches_pattern(request.resource, pattern) for pattern in policy.resources
        )
        action_match = any(
            _matches_pattern(request.action, pattern) for pattern in policy.actions
        )

        if not (resource_match and action_match):
            continue

        # Evaluate conditions
        conditions_met = all(
            _evaluate_condition(condition, request.subject, request.context)
            for condition in policy.conditions
        )

        if conditions_met:
            matching_policies.append(policy.id)
            decision = policy.effect
            reason = f"Matched policy: {policy.name}"
            break  # First matching policy wins (highest priority)

    elapsed = (time.perf_counter() - start) * 1000

    return PolicyEvaluationResponse(
        decision=decision,
        matching_policies=matching_policies,
        reason=reason,
        evaluation_time_ms=round(elapsed, 2),
    )


@router.post(
    "/from-natural-language",
    response_model=Policy,
    status_code=status.HTTP_201_CREATED,
    summary="Create policy from natural language",
    description="Use AI to create a policy from a natural language description.",
)
async def create_policy_from_natural_language(
    request: NaturalLanguagePolicyRequest,
    admin_user: AdminUser,
    settings: SettingsDep,
) -> Policy:
    """
    Create a policy from natural language using LLM.

    This endpoint uses Claude to interpret natural language policy
    descriptions and generate structured policy definitions.
    """
    # TODO: Implement actual LLM integration
    # For now, return a placeholder demonstrating the concept

    if not settings.anthropic.api_key.get_secret_value():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI features require ANTHROPIC_API_KEY configuration",
        )

    # Placeholder policy generation
    # In production, this would call Claude to parse the natural language
    policy = Policy(
        name=f"AI Generated Policy",
        description=f"Generated from: {request.description}",
        effect=PolicyEffect.ALLOW,
        resources=["*"],
        actions=["read"],
        conditions=[],
        priority=100,
    )

    _policies[policy.id] = policy
    return policy


def _matches_pattern(value: str, pattern: str) -> bool:
    """Check if a value matches a pattern (supports * wildcard)."""
    if pattern == "*":
        return True
    if "*" in pattern:
        import fnmatch

        return fnmatch.fnmatch(value, pattern)
    return value == pattern


def _evaluate_condition(
    condition: PolicyCondition,
    subject: dict,
    context: dict,
) -> bool:
    """Evaluate a single policy condition."""
    # Parse field path (e.g., "user.role" -> subject["role"])
    field_parts = condition.field.split(".")
    if field_parts[0] == "user":
        value = subject.get(field_parts[1]) if len(field_parts) > 1 else subject
    elif field_parts[0] == "context":
        value = context.get(field_parts[1]) if len(field_parts) > 1 else context
    else:
        value = None

    # Evaluate operator
    if condition.operator == "eq":
        return value == condition.value
    elif condition.operator == "ne":
        return value != condition.value
    elif condition.operator == "in":
        return value in condition.value if isinstance(condition.value, list) else False
    elif condition.operator == "contains":
        return condition.value in value if value else False
    elif condition.operator == "matches":
        import re

        return bool(re.match(condition.value, str(value))) if value else False

    return False
