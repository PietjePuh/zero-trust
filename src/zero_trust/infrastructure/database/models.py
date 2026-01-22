"""
SQLAlchemy ORM models for the Zero Trust platform.

Defines the database schema for users, policies, audit logs,
threat indicators, and risk assessments.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all ORM models."""

    pass


def generate_uuid() -> str:
    """Generate a UUID string for primary keys."""
    return str(uuid4())


def utc_now() -> datetime:
    """Get current UTC timestamp."""
    return datetime.now(UTC)


class User(Base):
    """User account model."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    roles: Mapped[list[str]] = mapped_column(JSON, default=list)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="user")
    risk_assessments: Mapped[list["RiskAssessment"]] = relationship(back_populates="user")

    def __repr__(self) -> str:
        return f"<User(id={self.id}, email={self.email})>"


class Policy(Base):
    """Security policy model."""

    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    effect: Mapped[str] = mapped_column(String(10), nullable=False)  # "allow" or "deny"
    resources: Mapped[list[str]] = mapped_column(JSON, default=list)
    actions: Mapped[list[str]] = mapped_column(JSON, default=list)
    conditions: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    priority: Mapped[int] = mapped_column(Integer, default=0)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )
    created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)

    __table_args__ = (Index("ix_policies_priority", "priority", "enabled"),)

    def __repr__(self) -> str:
        return f"<Policy(id={self.id}, name={self.name})>"


class AuditLog(Base):
    """Audit log for security events and actions."""

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    resource: Mapped[str] = mapped_column(String(255), nullable=False)
    result: Mapped[str] = mapped_column(String(20), nullable=False)  # "success", "denied", "error"
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    # Relationships
    user: Mapped[User | None] = relationship(back_populates="audit_logs")

    __table_args__ = (
        Index("ix_audit_logs_timestamp_action", "timestamp", "action"),
        Index("ix_audit_logs_user_timestamp", "user_id", "timestamp"),
    )

    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, action={self.action})>"


class ThreatIndicator(Base):
    """Threat indicator (IOC) storage model."""

    __tablename__ = "threat_indicators"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # ip, domain, hash, url
    value: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    mitre_tactics: Mapped[list[str]] = mapped_column(JSON, default=list)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)

    # For vector store reference
    vector_id: Mapped[str | None] = mapped_column(String(36), nullable=True)

    __table_args__ = (
        Index("ix_threat_type_value", "type", "value"),
        Index("ix_threat_category_severity", "category", "severity"),
    )

    def __repr__(self) -> str:
        return f"<ThreatIndicator(id={self.id}, type={self.type}, value={self.value[:50]})>"


class RiskAssessment(Base):
    """Risk assessment history model."""

    __tablename__ = "risk_assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )
    entity_type: Mapped[str] = mapped_column(String(20), nullable=False)  # user, device, request
    entity_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True, index=True
    )
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    factors: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    trigger: Mapped[str] = mapped_column(String(50), default="manual")
    requires_verification: Mapped[bool] = mapped_column(Boolean, default=False)
    context: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    # Relationships
    user: Mapped[User | None] = relationship(back_populates="risk_assessments")

    __table_args__ = (
        Index("ix_risk_entity", "entity_type", "entity_id", "timestamp"),
        Index("ix_risk_user_timestamp", "user_id", "timestamp"),
    )

    def __repr__(self) -> str:
        return f"<RiskAssessment(id={self.id}, entity={self.entity_type}:{self.entity_id})>"


class Session(Base):
    """User session tracking for zero-trust verification."""

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    device_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_activity: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    is_valid: Mapped[bool] = mapped_column(Boolean, default=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)

    __table_args__ = (
        Index("ix_sessions_user_valid", "user_id", "is_valid"),
        Index("ix_sessions_token", "token_hash"),
    )

    def __repr__(self) -> str:
        return f"<Session(id={self.id}, user_id={self.user_id})>"
