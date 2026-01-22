"""
Policy Engine Service.

Provides policy management and evaluation with support for:
- ABAC-style policy evaluation
- Policy combining algorithms
- LLM-assisted policy interpretation
"""

import fnmatch
import re
import time
from typing import Any

import structlog

from zero_trust.config import Settings, get_settings
from zero_trust.domain.policy.models import (
    ConditionOperator,
    Policy,
    PolicyCondition,
    PolicyDecision,
    PolicyEffect,
    PolicyEvaluationContext,
)

logger = structlog.get_logger(__name__)


class PolicyService:
    """
    Policy Engine Service.

    Handles policy CRUD operations and evaluation with support for:
    - Pattern matching on resources and actions
    - Condition evaluation with multiple operators
    - Policy combining algorithms
    - Optional LLM-assisted policy interpretation
    """

    def __init__(
        self,
        settings: Settings | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self._policies: dict[str, Policy] = {}
        self._llm_client = None

        # Initialize with default policies
        self._init_default_policies()

    def _init_default_policies(self) -> None:
        """Initialize default zero-trust policies."""
        # Default deny policy (lowest priority)
        self._policies["default_deny"] = Policy(
            id="default_deny",
            name="Default Deny",
            description="Deny all access by default (zero trust principle)",
            effect=PolicyEffect.DENY,
            resources=["*"],
            actions=["*"],
            conditions=[],
            priority=0,
        )

        # Admin full access (highest priority)
        self._policies["admin_allow"] = Policy(
            id="admin_allow",
            name="Admin Full Access",
            description="Allow administrators full access",
            effect=PolicyEffect.ALLOW,
            resources=["*"],
            actions=["*"],
            conditions=[
                PolicyCondition(
                    field="subject.roles",
                    operator=ConditionOperator.CONTAINS,
                    value="admin",
                )
            ],
            priority=1000,
        )

    async def evaluate(
        self,
        context: PolicyEvaluationContext,
        use_ai_reasoning: bool = False,
    ) -> PolicyDecision:
        """
        Evaluate policies for a given context.

        This is the Policy Decision Point (PDP) - the core evaluation logic.

        Args:
            context: The evaluation context containing subject, resource, action
            use_ai_reasoning: Whether to include AI-generated explanation

        Returns:
            PolicyDecision with the evaluation result
        """
        start_time = time.perf_counter()

        await logger.ainfo(
            "policy_evaluation_started",
            resource=context.resource,
            action=context.action,
            subject_id=context.subject.get("id"),
        )

        # Get applicable policies sorted by priority (highest first)
        applicable_policies = self._get_applicable_policies(context)

        matching_policies: list[str] = []
        decision_policy: Policy | None = None
        reason = "No matching policy found"

        # Evaluate policies in priority order (first match wins)
        for policy in applicable_policies:
            if not policy.enabled:
                continue

            # Check if all conditions are met
            if self._evaluate_conditions(policy.conditions, context):
                matching_policies.append(policy.id)
                decision_policy = policy
                reason = f"Matched policy: {policy.name}"
                break

        # Default to deny if no policy matched
        effect = decision_policy.effect if decision_policy else PolicyEffect.DENY

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # Get AI explanation if requested
        ai_explanation = None
        if use_ai_reasoning and decision_policy:
            ai_explanation = await self._get_ai_explanation(context, decision_policy)

        await logger.ainfo(
            "policy_evaluation_completed",
            resource=context.resource,
            action=context.action,
            effect=effect.value,
            policy_id=decision_policy.id if decision_policy else None,
            elapsed_ms=round(elapsed_ms, 2),
        )

        return PolicyDecision(
            effect=effect,
            policy_id=decision_policy.id if decision_policy else None,
            policy_name=decision_policy.name if decision_policy else None,
            reason=reason,
            matching_policies=matching_policies,
            evaluation_time_ms=round(elapsed_ms, 2),
            ai_explanation=ai_explanation,
        )

    def _get_applicable_policies(
        self,
        context: PolicyEvaluationContext,
    ) -> list[Policy]:
        """Get policies that apply to the given resource and action."""
        applicable = []

        for policy in self._policies.values():
            # Check resource match
            resource_match = any(
                self._matches_pattern(context.resource, pattern)
                for pattern in policy.resources
            )

            # Check action match
            action_match = any(
                self._matches_pattern(context.action, pattern)
                for pattern in policy.actions
            )

            if resource_match and action_match:
                applicable.append(policy)

        # Sort by priority (highest first)
        return sorted(applicable, key=lambda p: p.priority, reverse=True)

    def _evaluate_conditions(
        self,
        conditions: list[PolicyCondition],
        context: PolicyEvaluationContext,
    ) -> bool:
        """Evaluate all conditions (AND logic)."""
        if not conditions:
            return True

        return all(
            self._evaluate_condition(condition, context)
            for condition in conditions
        )

    def _evaluate_condition(
        self,
        condition: PolicyCondition,
        context: PolicyEvaluationContext,
    ) -> bool:
        """Evaluate a single condition."""
        # Get the field value from context
        value = self._get_field_value(condition.field, context)

        op = condition.operator
        expected = condition.value

        try:
            if op == ConditionOperator.EQUALS:
                return value == expected
            elif op == ConditionOperator.NOT_EQUALS:
                return value != expected
            elif op == ConditionOperator.IN:
                return value in expected if isinstance(expected, list) else False
            elif op == ConditionOperator.NOT_IN:
                return value not in expected if isinstance(expected, list) else True
            elif op == ConditionOperator.CONTAINS:
                if isinstance(value, list):
                    return expected in value
                elif isinstance(value, str):
                    return expected in value
                return False
            elif op == ConditionOperator.MATCHES:
                return bool(re.match(expected, str(value))) if value else False
            elif op == ConditionOperator.GREATER_THAN:
                return value > expected if value is not None else False
            elif op == ConditionOperator.LESS_THAN:
                return value < expected if value is not None else False
            elif op == ConditionOperator.GREATER_OR_EQUAL:
                return value >= expected if value is not None else False
            elif op == ConditionOperator.LESS_OR_EQUAL:
                return value <= expected if value is not None else False
            elif op == ConditionOperator.EXISTS:
                return value is not None
            elif op == ConditionOperator.NOT_EXISTS:
                return value is None
        except Exception:
            return False

        return False

    def _get_field_value(
        self,
        field_path: str,
        context: PolicyEvaluationContext,
    ) -> Any:
        """Extract field value from context using dot notation."""
        parts = field_path.split(".")

        if not parts:
            return None

        # Determine root object
        root = parts[0]
        if root == "subject":
            obj: Any = context.subject
        elif root == "environment":
            obj = context.environment
        elif root == "resource":
            return context.resource
        elif root == "action":
            return context.action
        else:
            return None

        # Navigate to nested value
        for part in parts[1:]:
            if isinstance(obj, dict):
                obj = obj.get(part)
            elif hasattr(obj, part):
                obj = getattr(obj, part)
            else:
                return None

            if obj is None:
                return None

        return obj

    def _matches_pattern(self, value: str, pattern: str) -> bool:
        """Check if value matches pattern (supports wildcards)."""
        if pattern == "*":
            return True
        return fnmatch.fnmatch(value, pattern)

    async def _get_ai_explanation(
        self,
        context: PolicyEvaluationContext,
        policy: Policy,
    ) -> str | None:
        """Get AI-generated explanation for the policy decision."""
        if not self.settings.anthropic.api_key.get_secret_value():
            return None

        try:
            if self._llm_client is None:
                import anthropic

                self._llm_client = anthropic.Anthropic(
                    api_key=self.settings.anthropic.api_key.get_secret_value()
                )

            prompt = f"""Explain this security policy decision in one sentence:

Policy: {policy.name}
Effect: {policy.effect.value}
Resource: {context.resource}
Action: {context.action}
Subject roles: {context.subject.get('roles', [])}

Explanation:"""

            message = self._llm_client.messages.create(
                model=self.settings.anthropic.model,
                max_tokens=100,
                temperature=0,
                messages=[{"role": "user", "content": prompt}],
            )

            return message.content[0].text.strip()

        except Exception as e:
            await logger.awarning("ai_explanation_failed", error=str(e))
            return None

    # Policy CRUD operations

    async def create_policy(self, policy: Policy) -> Policy:
        """Create a new policy."""
        self._policies[policy.id] = policy
        await logger.ainfo("policy_created", policy_id=policy.id, name=policy.name)
        return policy

    async def get_policy(self, policy_id: str) -> Policy | None:
        """Get a policy by ID."""
        return self._policies.get(policy_id)

    async def list_policies(self) -> list[Policy]:
        """List all policies."""
        return list(self._policies.values())

    async def update_policy(self, policy: Policy) -> Policy:
        """Update an existing policy."""
        if policy.id not in self._policies:
            raise ValueError(f"Policy {policy.id} not found")
        self._policies[policy.id] = policy
        await logger.ainfo("policy_updated", policy_id=policy.id)
        return policy

    async def delete_policy(self, policy_id: str) -> bool:
        """Delete a policy."""
        if policy_id in self._policies:
            del self._policies[policy_id]
            await logger.ainfo("policy_deleted", policy_id=policy_id)
            return True
        return False
