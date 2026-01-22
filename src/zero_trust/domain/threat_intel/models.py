"""
Threat Intelligence domain models.

Defines the core data structures for threat intelligence operations.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ThreatSeverity(str, Enum):
    """Threat severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatCategory(str, Enum):
    """Categories of threats."""

    MALWARE = "malware"
    VULNERABILITY = "vulnerability"
    EXPLOIT = "exploit"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    APT = "apt"
    DDOS = "ddos"
    DATA_BREACH = "data_breach"
    INSIDER_THREAT = "insider_threat"
    OTHER = "other"


class IndicatorType(str, Enum):
    """Types of threat indicators (IOCs)."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    CVE = "cve"
    FILE_NAME = "file_name"
    REGISTRY_KEY = "registry_key"


class ThreatIndicator(BaseModel):
    """A threat indicator (IOC)."""

    id: str
    type: IndicatorType
    value: str
    severity: ThreatSeverity
    category: ThreatCategory
    description: str
    confidence: float = Field(ge=0.0, le=1.0)
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: list[str] = []
    mitre_tactics: list[str] = []
    mitre_techniques: list[str] = []
    related_indicators: list[str] = []
    metadata: dict[str, Any] = {}


class ThreatQuery(BaseModel):
    """Query parameters for threat intelligence search."""

    query: str = Field(min_length=1, description="Search query")
    types: list[IndicatorType] | None = None
    categories: list[ThreatCategory] | None = None
    min_severity: ThreatSeverity | None = None
    min_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    sources: list[str] | None = None
    tags: list[str] | None = None
    limit: int = Field(default=10, ge=1, le=100)
    use_semantic_search: bool = True


class ThreatAnalysisResult(BaseModel):
    """Result of AI-powered threat analysis."""

    threat_level: ThreatSeverity
    summary: str
    identified_threats: list[str]
    related_indicators: list[ThreatIndicator] = []
    mitre_techniques: list[str] = []
    recommendations: list[str] = []
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str | None = None


class MitreAttackTechnique(BaseModel):
    """MITRE ATT&CK technique information."""

    technique_id: str
    name: str
    description: str
    tactic: str
    platforms: list[str]
    data_sources: list[str] = []
    detection: str | None = None
    mitigation: str | None = None


class CVEInfo(BaseModel):
    """CVE vulnerability information."""

    cve_id: str
    description: str
    severity: ThreatSeverity
    cvss_v3_score: float | None = Field(ge=0.0, le=10.0, default=None)
    cvss_v3_vector: str | None = None
    affected_products: list[str] = []
    references: list[str] = []
    published_date: datetime
    modified_date: datetime
    exploit_available: bool = False
    patch_available: bool = False
    cwe_ids: list[str] = []
