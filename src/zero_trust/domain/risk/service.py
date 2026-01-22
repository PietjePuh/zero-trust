"""
Risk Assessment Service.

Provides real-time risk scoring combining multiple signals:
- Authentication patterns
- Behavioral analysis
- Device posture
- Location/network context
- Threat intelligence correlation
"""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from zero_trust.config import Settings, get_settings
from zero_trust.domain.risk.models import (
    RiskAssessment,
    RiskContext,
    RiskFactor,
    RiskFactorType,
    RiskLevel,
)

logger = structlog.get_logger(__name__)


class RiskAssessmentService:
    """
    Risk Assessment Service.

    Calculates risk scores by combining multiple risk factors with
    configurable weights. Supports both synchronous assessment and
    continuous monitoring.
    """

    def __init__(
        self,
        settings: Settings | None = None,
    ) -> None:
        self.settings = settings or get_settings()

        # Default factor weights
        self.factor_weights = {
            RiskFactorType.AUTHENTICATION: 0.25,
            RiskFactorType.BEHAVIORAL: 0.20,
            RiskFactorType.DEVICE: 0.20,
            RiskFactorType.LOCATION: 0.15,
            RiskFactorType.NETWORK: 0.10,
            RiskFactorType.THREAT_INTEL: 0.10,
        }

        # Risk level thresholds
        self.thresholds = {
            RiskLevel.MINIMAL: (0.0, 0.2),
            RiskLevel.LOW: (0.2, 0.4),
            RiskLevel.MEDIUM: (0.4, 0.6),
            RiskLevel.HIGH: (0.6, 0.8),
            RiskLevel.CRITICAL: (0.8, 1.0),
        }

    async def assess(self, context: RiskContext) -> RiskAssessment:
        """
        Perform comprehensive risk assessment.

        Evaluates all risk factors and produces a weighted risk score.
        """
        await logger.ainfo(
            "risk_assessment_started",
            entity_type=context.entity_type,
            entity_id=context.entity_id,
        )

        factors: list[RiskFactor] = []

        # Assess each risk factor
        factors.append(await self._assess_authentication(context))
        factors.append(await self._assess_behavioral(context))
        factors.append(await self._assess_device(context))
        factors.append(await self._assess_location(context))
        factors.append(await self._assess_network(context))
        factors.append(await self._assess_threat_intel(context))

        # Calculate weighted risk score
        total_weight = sum(f.weight for f in factors)
        risk_score = sum(f.score * f.weight for f in factors) / total_weight

        # Determine risk level
        risk_level = self._score_to_level(risk_score)

        # Generate recommendations
        recommendations = self._generate_recommendations(factors, risk_level)

        # Determine action requirements
        requires_mfa = risk_score > 0.5
        requires_verification = risk_score > 0.7
        allow_action = risk_score < 0.9

        assessment = RiskAssessment(
            id=f"risk_{uuid4().hex[:12]}",
            timestamp=datetime.now(UTC),
            context=context,
            risk_score=round(risk_score, 4),
            risk_level=risk_level,
            factors=factors,
            recommendations=recommendations,
            requires_mfa=requires_mfa,
            requires_verification=requires_verification,
            allow_action=allow_action,
        )

        await logger.ainfo(
            "risk_assessment_completed",
            assessment_id=assessment.id,
            risk_score=assessment.risk_score,
            risk_level=assessment.risk_level.value,
        )

        return assessment

    async def _assess_authentication(self, context: RiskContext) -> RiskFactor:
        """Assess authentication-related risk factors."""
        score = 0.1  # Base score for authenticated user
        details: dict[str, Any] = {}
        mitigations: list[str] = []

        session_info = context.session_info

        # Check failed login attempts
        failed_attempts = session_info.get("failed_attempts_24h", 0)
        if failed_attempts > 5:
            score += 0.3
            details["failed_attempts"] = failed_attempts
            mitigations.append("Investigate recent failed login attempts")
        elif failed_attempts > 2:
            score += 0.1
            details["failed_attempts"] = failed_attempts

        # Check if using MFA
        if not session_info.get("mfa_verified", False):
            score += 0.2
            details["mfa_verified"] = False
            mitigations.append("Enable multi-factor authentication")
        else:
            details["mfa_verified"] = True

        # Check session age
        session_age_hours = session_info.get("session_age_hours", 0)
        if session_age_hours > 24:
            score += 0.15
            details["session_age_hours"] = session_age_hours
            mitigations.append("Re-authenticate for sensitive operations")

        return RiskFactor(
            name="Authentication Risk",
            type=RiskFactorType.AUTHENTICATION,
            description="Risk based on authentication patterns and session state",
            score=min(score, 1.0),
            weight=self.factor_weights[RiskFactorType.AUTHENTICATION],
            details=details,
            mitigations=mitigations,
        )

    async def _assess_behavioral(self, context: RiskContext) -> RiskFactor:
        """Assess behavioral anomaly risk factors."""
        score = 0.1
        details: dict[str, Any] = {}
        mitigations: list[str] = []

        additional = context.additional_context

        # Check for unusual access patterns
        if additional.get("unusual_time_access", False):
            score += 0.2
            details["unusual_time"] = True
            mitigations.append("Verify user identity for off-hours access")

        # Check for unusual resource access
        if additional.get("unusual_resource_access", False):
            score += 0.25
            details["unusual_resource"] = True
            mitigations.append("Review resource access permissions")

        # Check request velocity
        requests_per_minute = additional.get("requests_per_minute", 0)
        if requests_per_minute > 100:
            score += 0.3
            details["high_velocity"] = True
            details["requests_per_minute"] = requests_per_minute
            mitigations.append("Investigate potential automated access")
        elif requests_per_minute > 50:
            score += 0.1
            details["requests_per_minute"] = requests_per_minute

        return RiskFactor(
            name="Behavioral Risk",
            type=RiskFactorType.BEHAVIORAL,
            description="Risk based on behavioral patterns and anomalies",
            score=min(score, 1.0),
            weight=self.factor_weights[RiskFactorType.BEHAVIORAL],
            details=details,
            mitigations=mitigations,
        )

    async def _assess_device(self, context: RiskContext) -> RiskFactor:
        """Assess device posture risk factors."""
        score = 0.15
        details: dict[str, Any] = {}
        mitigations: list[str] = []

        device_info = context.device_info

        # Check if device is known/trusted
        if not device_info.get("is_known", True):
            score += 0.25
            details["unknown_device"] = True
            mitigations.append("Register and verify new device")

        # Check OS security status
        if not device_info.get("os_updated", True):
            score += 0.2
            details["os_outdated"] = True
            mitigations.append("Update operating system to latest version")

        # Check disk encryption
        if not device_info.get("disk_encrypted", True):
            score += 0.15
            details["unencrypted"] = True
            mitigations.append("Enable full disk encryption")

        # Check security software
        if not device_info.get("security_software_active", True):
            score += 0.15
            details["no_security_software"] = True
            mitigations.append("Install and activate endpoint protection")

        return RiskFactor(
            name="Device Risk",
            type=RiskFactorType.DEVICE,
            description="Risk based on device security posture",
            score=min(score, 1.0),
            weight=self.factor_weights[RiskFactorType.DEVICE],
            details=details,
            mitigations=mitigations,
        )

    async def _assess_location(self, context: RiskContext) -> RiskFactor:
        """Assess location-based risk factors."""
        score = 0.1
        details: dict[str, Any] = {}
        mitigations: list[str] = []

        additional = context.additional_context

        # Check for impossible travel
        if additional.get("impossible_travel", False):
            score += 0.5
            details["impossible_travel"] = True
            mitigations.append("Verify user identity - impossible travel detected")

        # Check if location is known
        if additional.get("unknown_location", False):
            score += 0.2
            details["unknown_location"] = True
            mitigations.append("Verify access from new location")

        # Check for high-risk country
        if additional.get("high_risk_country", False):
            score += 0.3
            details["high_risk_country"] = True
            mitigations.append("Apply enhanced verification for high-risk region")

        return RiskFactor(
            name="Location Risk",
            type=RiskFactorType.LOCATION,
            description="Risk based on geographic location",
            score=min(score, 1.0),
            weight=self.factor_weights[RiskFactorType.LOCATION],
            details=details,
            mitigations=mitigations,
        )

    async def _assess_network(self, context: RiskContext) -> RiskFactor:
        """Assess network-based risk factors."""
        score = 0.1
        details: dict[str, Any] = {}
        mitigations: list[str] = []

        # Check if using VPN/proxy
        if context.additional_context.get("using_vpn", False):
            score += 0.1
            details["vpn_detected"] = True

        # Check if using Tor
        if context.additional_context.get("using_tor", False):
            score += 0.4
            details["tor_detected"] = True
            mitigations.append("Block or verify Tor exit node access")

        # Check if IP is on blocklist
        if context.additional_context.get("ip_blocklisted", False):
            score += 0.5
            details["blocklisted_ip"] = True
            mitigations.append("Block access from known malicious IP")

        # Check for corporate network
        if context.additional_context.get("corporate_network", True):
            score -= 0.05  # Slight reduction for known good network
            details["corporate_network"] = True

        return RiskFactor(
            name="Network Risk",
            type=RiskFactorType.NETWORK,
            description="Risk based on network characteristics",
            score=max(min(score, 1.0), 0.0),
            weight=self.factor_weights[RiskFactorType.NETWORK],
            details=details,
            mitigations=mitigations,
        )

    async def _assess_threat_intel(self, context: RiskContext) -> RiskFactor:
        """Assess threat intelligence correlation risk."""
        score = 0.05
        details: dict[str, Any] = {}
        mitigations: list[str] = []

        # Check if IP matches known threats
        if context.additional_context.get("ip_threat_match", False):
            score += 0.6
            details["ip_threat_match"] = True
            mitigations.append("Block access - IP matches threat intelligence")

        # Check if user agent matches known malware
        if context.additional_context.get("ua_threat_match", False):
            score += 0.4
            details["ua_threat_match"] = True
            mitigations.append("Investigate potential malware infection")

        # Check for active campaign targeting
        if context.additional_context.get("active_campaign_target", False):
            score += 0.3
            details["campaign_target"] = True
            mitigations.append("Apply enhanced monitoring - active threat campaign")

        return RiskFactor(
            name="Threat Intelligence",
            type=RiskFactorType.THREAT_INTEL,
            description="Risk based on threat intelligence correlation",
            score=min(score, 1.0),
            weight=self.factor_weights[RiskFactorType.THREAT_INTEL],
            details=details,
            mitigations=mitigations,
        )

    def _score_to_level(self, score: float) -> RiskLevel:
        """Convert numeric score to risk level."""
        for level, (min_score, max_score) in self.thresholds.items():
            if min_score <= score < max_score:
                return level
        return RiskLevel.CRITICAL

    def _generate_recommendations(
        self,
        factors: list[RiskFactor],
        risk_level: RiskLevel,
    ) -> list[str]:
        """Generate recommendations based on risk factors."""
        recommendations: list[str] = []

        # Collect all mitigations from high-scoring factors
        for factor in factors:
            if factor.score > 0.3:
                recommendations.extend(factor.mitigations)

        # Add level-specific recommendations
        if risk_level == RiskLevel.HIGH:
            recommendations.append("Require step-up authentication")
            recommendations.append("Enable enhanced session monitoring")
        elif risk_level == RiskLevel.CRITICAL:
            recommendations.append("Consider blocking access pending verification")
            recommendations.append("Alert security team for immediate review")

        # Deduplicate while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)

        return unique_recommendations
