"""
Threat Intelligence Service.

Provides threat intelligence operations including:
- IOC lookups and enrichment
- Semantic search across threat data
- AI-powered threat analysis
- CVE and MITRE ATT&CK lookups
"""

from datetime import UTC, datetime
from typing import Any

import structlog

from zero_trust.config import Settings, get_settings
from zero_trust.domain.threat_intel.models import (
    CVEInfo,
    MitreAttackTechnique,
    ThreatAnalysisResult,
    ThreatCategory,
    ThreatIndicator,
    ThreatQuery,
    ThreatSeverity,
)
from zero_trust.infrastructure.vector_store.client import VectorStoreClient

logger = structlog.get_logger(__name__)


class ThreatIntelService:
    """
    Threat Intelligence Service.

    Handles all threat intelligence operations including lookups,
    semantic search, and AI-powered analysis.
    """

    def __init__(
        self,
        vector_store: VectorStoreClient | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self._vector_store = vector_store
        self._llm_client = None  # Initialized lazily

    @property
    def vector_store(self) -> VectorStoreClient:
        """Get vector store client."""
        if self._vector_store is None:
            from zero_trust.infrastructure.vector_store import get_vector_store

            self._vector_store = get_vector_store(self.settings)
        return self._vector_store

    async def search(self, query: ThreatQuery) -> list[ThreatIndicator]:
        """
        Search for threat indicators.

        Uses hybrid search combining semantic and keyword matching.
        """
        await logger.ainfo(
            "threat_search_started",
            query=query.query,
            limit=query.limit,
        )

        # Build filters for vector store
        filters: dict[str, Any] = {}
        if query.min_severity:
            filters["severity"] = query.min_severity.value
        if query.categories and len(query.categories) == 1:
            filters["category"] = query.categories[0].value

        try:
            results = await self.vector_store.search_threats(
                query=query.query,
                limit=query.limit,
                filters=filters if filters else None,
                alpha=0.5 if query.use_semantic_search else 0.0,
            )

            indicators = []
            for result in results:
                try:
                    indicator = self._result_to_indicator(result)
                    indicators.append(indicator)
                except Exception as e:
                    await logger.awarning(
                        "failed_to_parse_indicator",
                        result_id=result.get("id"),
                        error=str(e),
                    )

            await logger.ainfo(
                "threat_search_completed",
                query=query.query,
                results_count=len(indicators),
            )

            return indicators

        except Exception as e:
            await logger.aerror(
                "threat_search_failed",
                query=query.query,
                error=str(e),
            )
            # Return empty results on error rather than failing
            return []

    async def lookup_indicator(self, indicator_type: str, value: str) -> ThreatIndicator | None:
        """
        Look up a specific indicator by type and value.

        Performs exact match lookup.
        """
        query = ThreatQuery(
            query=value,
            use_semantic_search=False,
            limit=1,
        )

        results = await self.search(query)

        for indicator in results:
            if indicator.value.lower() == value.lower():
                return indicator

        return None

    async def analyze_context(
        self,
        context: str,
        include_recommendations: bool = True,
    ) -> ThreatAnalysisResult:
        """
        Analyze security context using AI.

        Uses Claude to analyze security-related text and identify
        potential threats, relevant MITRE techniques, and recommendations.
        """
        await logger.ainfo("threat_analysis_started", context_length=len(context))

        # Check if LLM is configured
        if not self.settings.anthropic.api_key.get_secret_value():
            return ThreatAnalysisResult(
                threat_level=ThreatSeverity.INFO,
                summary="AI analysis unavailable - API key not configured",
                identified_threats=[],
                recommendations=[],
                confidence=0.0,
            )

        try:
            # Initialize Anthropic client if needed
            if self._llm_client is None:
                import anthropic

                self._llm_client = anthropic.Anthropic(
                    api_key=self.settings.anthropic.api_key.get_secret_value()
                )

            # Build analysis prompt
            prompt = self._build_analysis_prompt(context, include_recommendations)

            # Call Claude for analysis
            message = self._llm_client.messages.create(
                model=self.settings.anthropic.model,
                max_tokens=self.settings.anthropic.max_tokens,
                temperature=self.settings.anthropic.temperature,
                messages=[{"role": "user", "content": prompt}],
            )

            # Parse response
            response_text = message.content[0].text
            result = self._parse_analysis_response(response_text)

            await logger.ainfo(
                "threat_analysis_completed",
                threat_level=result.threat_level.value,
                threats_found=len(result.identified_threats),
            )

            return result

        except Exception as e:
            await logger.aerror("threat_analysis_failed", error=str(e))
            return ThreatAnalysisResult(
                threat_level=ThreatSeverity.INFO,
                summary=f"Analysis failed: {str(e)}",
                identified_threats=[],
                recommendations=[],
                confidence=0.0,
            )

    async def get_cve(self, cve_id: str) -> CVEInfo | None:
        """
        Get CVE information.

        TODO: Integrate with NVD API for real-time data.
        """
        # Placeholder - would integrate with NVD API
        return CVEInfo(
            cve_id=cve_id.upper(),
            description="CVE lookup placeholder - NVD integration pending",
            severity=ThreatSeverity.MEDIUM,
            cvss_v3_score=5.0,
            affected_products=[],
            references=[f"https://nvd.nist.gov/vuln/detail/{cve_id.upper()}"],
            published_date=datetime.now(UTC),
            modified_date=datetime.now(UTC),
        )

    async def get_mitre_technique(self, technique_id: str) -> MitreAttackTechnique | None:
        """
        Get MITRE ATT&CK technique information.

        TODO: Integrate with MITRE ATT&CK STIX data.
        """
        # Placeholder - would integrate with MITRE ATT&CK
        return MitreAttackTechnique(
            technique_id=technique_id.upper(),
            name="Technique lookup placeholder",
            description="MITRE ATT&CK integration pending",
            tactic="unknown",
            platforms=["Windows", "Linux", "macOS"],
        )

    async def ingest_indicators(
        self,
        indicators: list[ThreatIndicator],
    ) -> dict[str, Any]:
        """
        Ingest threat indicators into the vector store.

        Processes and indexes indicators for semantic search.
        """
        await logger.ainfo("indicator_ingestion_started", count=len(indicators))

        success_count = 0
        error_count = 0

        for indicator in indicators:
            try:
                await self.vector_store.add_threat_indicator(
                    indicator_id=indicator.id,
                    indicator_type=indicator.type.value,
                    value=indicator.value,
                    description=indicator.description,
                    severity=indicator.severity.value,
                    category=indicator.category.value,
                    confidence=indicator.confidence,
                    source=indicator.source,
                    tags=indicator.tags,
                    mitre_tactics=indicator.mitre_tactics,
                    mitre_techniques=indicator.mitre_techniques,
                )
                success_count += 1
            except Exception as e:
                await logger.awarning(
                    "indicator_ingestion_failed",
                    indicator_id=indicator.id,
                    error=str(e),
                )
                error_count += 1

        await logger.ainfo(
            "indicator_ingestion_completed",
            success=success_count,
            errors=error_count,
        )

        return {
            "total": len(indicators),
            "success": success_count,
            "errors": error_count,
        }

    def _result_to_indicator(self, result: dict[str, Any]) -> ThreatIndicator:
        """Convert vector store result to ThreatIndicator."""
        from zero_trust.domain.threat_intel.models import IndicatorType

        return ThreatIndicator(
            id=result.get("indicator_id", result.get("id", "")),
            type=IndicatorType(result.get("type", "ip")),
            value=result.get("value", ""),
            severity=ThreatSeverity(result.get("severity", "medium")),
            category=ThreatCategory(result.get("category", "other")),
            description=result.get("description", ""),
            confidence=result.get("confidence", 0.5),
            source=result.get("source", "unknown"),
            first_seen=datetime.now(UTC),  # Would come from actual data
            last_seen=datetime.now(UTC),
            tags=result.get("tags", []),
            mitre_tactics=result.get("mitre_tactics", []),
            mitre_techniques=result.get("mitre_techniques", []),
        )

    def _build_analysis_prompt(self, context: str, include_recommendations: bool) -> str:
        """Build the analysis prompt for Claude."""
        prompt = f"""Analyze the following security context and identify potential threats.

Context:
{context}

Provide your analysis in the following format:

THREAT_LEVEL: [CRITICAL|HIGH|MEDIUM|LOW|INFO]
SUMMARY: [Brief summary of the security situation]
IDENTIFIED_THREATS:
- [Threat 1]
- [Threat 2]
MITRE_TECHNIQUES:
- [T1234 - Technique Name]
CONFIDENCE: [0.0-1.0]
"""

        if include_recommendations:
            prompt += """
RECOMMENDATIONS:
- [Recommendation 1]
- [Recommendation 2]
"""

        prompt += "\nProvide only the structured response, no additional commentary."

        return prompt

    def _parse_analysis_response(self, response: str) -> ThreatAnalysisResult:
        """Parse Claude's analysis response."""
        lines = response.strip().split("\n")

        threat_level = ThreatSeverity.MEDIUM
        summary = ""
        identified_threats: list[str] = []
        mitre_techniques: list[str] = []
        recommendations: list[str] = []
        confidence = 0.5

        current_section = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            if line.startswith("THREAT_LEVEL:"):
                level_str = line.split(":", 1)[1].strip().upper()
                try:
                    threat_level = ThreatSeverity(level_str.lower())
                except ValueError:
                    pass
            elif line.startswith("SUMMARY:"):
                summary = line.split(":", 1)[1].strip()
            elif line.startswith("CONFIDENCE:"):
                try:
                    confidence = float(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif line.startswith("IDENTIFIED_THREATS:"):
                current_section = "threats"
            elif line.startswith("MITRE_TECHNIQUES:"):
                current_section = "mitre"
            elif line.startswith("RECOMMENDATIONS:"):
                current_section = "recommendations"
            elif line.startswith("- "):
                item = line[2:].strip()
                if current_section == "threats":
                    identified_threats.append(item)
                elif current_section == "mitre":
                    mitre_techniques.append(item)
                elif current_section == "recommendations":
                    recommendations.append(item)

        return ThreatAnalysisResult(
            threat_level=threat_level,
            summary=summary,
            identified_threats=identified_threats,
            mitre_techniques=mitre_techniques,
            recommendations=recommendations,
            confidence=confidence,
            reasoning=response,
        )
