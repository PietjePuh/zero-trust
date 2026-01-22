"""
Weaviate collection schemas.

Defines the schema structures for vector store collections.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ThreatIntelDocument(BaseModel):
    """Document schema for threat intelligence collection."""

    indicator_id: str
    type: str = Field(description="Indicator type: ip, domain, hash, url, email")
    value: str
    description: str
    severity: str = Field(description="critical, high, medium, low, info")
    category: str
    confidence: float = Field(ge=0.0, le=1.0)
    source: str
    tags: list[str] = []
    mitre_tactics: list[str] = []
    mitre_techniques: list[str] = []


class SecurityAdvisoryDocument(BaseModel):
    """Document schema for security advisory collection."""

    advisory_id: str
    title: str
    description: str
    severity: str
    cvss_score: float | None = Field(ge=0.0, le=10.0, default=None)
    affected_products: list[str] = []
    cve_ids: list[str] = []
    references: list[str] = []
    published_date: datetime
    remediation: str | None = None


class SearchResult(BaseModel):
    """Generic search result with score."""

    id: str
    score: float | None = None
    properties: dict[str, Any]


# Collection configuration constants
class ThreatIntelCollection:
    """Configuration for the ThreatIntel collection."""

    NAME = "ThreatIntel"
    DESCRIPTION = "Threat indicators and IOCs for semantic search"


class SecurityAdvisoryCollection:
    """Configuration for the SecurityAdvisory collection."""

    NAME = "SecurityAdvisory"
    DESCRIPTION = "Security advisories, CVEs, and vulnerability information"
