"""
Configuration management using pydantic-settings.

All configuration is loaded from environment variables with sensible defaults.
Secrets are never logged or exposed in error messages.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    """Database configuration."""

    model_config = SettingsConfigDict(env_prefix="DATABASE_")

    url: SecretStr = Field(
        default=SecretStr("postgresql+asyncpg://postgres:postgres@localhost:5432/zero_trust"),
        description="Database connection URL",
    )
    pool_size: int = Field(default=5, ge=1, le=20)
    max_overflow: int = Field(default=10, ge=0, le=50)
    echo: bool = Field(default=False, description="Echo SQL queries (debug only)")


class WeaviateSettings(BaseSettings):
    """Weaviate vector store configuration."""

    model_config = SettingsConfigDict(env_prefix="WEAVIATE_")

    url: str = Field(default="http://localhost:8080")
    api_key: SecretStr | None = Field(default=None)
    timeout: int = Field(default=30, ge=5, le=120)


class AnthropicSettings(BaseSettings):
    """Anthropic Claude API configuration."""

    model_config = SettingsConfigDict(env_prefix="ANTHROPIC_")

    api_key: SecretStr = Field(default=SecretStr(""))
    model: str = Field(default="claude-sonnet-4-20250514")
    max_tokens: int = Field(default=4096, ge=1, le=8192)
    temperature: float = Field(default=0.0, ge=0.0, le=1.0)


class SecuritySettings(BaseSettings):
    """Security configuration."""

    model_config = SettingsConfigDict(env_prefix="")

    secret_key: SecretStr = Field(
        default=SecretStr("CHANGE-ME-IN-PRODUCTION-USE-OPENSSL-RAND-HEX-32"),
        alias="SECRET_KEY",
    )
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    jwt_expiration_minutes: int = Field(default=30, ge=5, le=1440, alias="JWT_EXPIRATION_MINUTES")
    allowed_origins: list[str] = Field(
        default=["http://localhost:3000", "http://localhost:8000"],
        alias="ALLOWED_ORIGINS",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_secret_key_default(self) -> bool:
        """Check if secret key is still the default (insecure)."""
        return "CHANGE-ME" in self.secret_key.get_secret_value()


class RedisSettings(BaseSettings):
    """Redis configuration for caching and rate limiting."""

    model_config = SettingsConfigDict(env_prefix="REDIS_")

    url: str = Field(default="redis://localhost:6379/0")
    max_connections: int = Field(default=10, ge=1, le=100)


class Settings(BaseSettings):
    """
    Main application settings.

    Aggregates all configuration sections and provides validation.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # Application
    app_name: str = Field(default="zero-trust")
    app_env: Literal["development", "staging", "production"] = Field(default="development")
    debug: bool = Field(default=False)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(default="INFO")

    # API Server
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000, ge=1, le=65535)
    api_reload: bool = Field(default=False)

    # Sub-configurations
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    weaviate: WeaviateSettings = Field(default_factory=WeaviateSettings)
    anthropic: AnthropicSettings = Field(default_factory=AnthropicSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.app_env == "production"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.app_env == "development"

    def validate_production_settings(self) -> list[str]:
        """
        Validate settings for production deployment.

        Returns a list of configuration issues that must be resolved.
        """
        issues: list[str] = []

        if self.is_production:
            if self.debug:
                issues.append("DEBUG must be False in production")
            if self.security.is_secret_key_default:
                issues.append("SECRET_KEY must be changed from default in production")
            if not self.anthropic.api_key.get_secret_value():
                issues.append("ANTHROPIC_API_KEY is required for AI features")
            if "localhost" in self.security.allowed_origins:
                issues.append("ALLOWED_ORIGINS should not contain localhost in production")

        return issues


@lru_cache
def get_settings() -> Settings:
    """
    Get cached settings instance.

    Settings are loaded once and cached for the lifetime of the application.
    Use dependency injection in FastAPI routes for testability.
    """
    return Settings()
