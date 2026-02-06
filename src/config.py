"""
Configuration management using Pydantic Settings.

Loads configuration from environment variables and .env files.
All settings are validated and typed.
"""

from functools import lru_cache
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -------------------------------------------------------------------------
    # Application
    # -------------------------------------------------------------------------
    APP_NAME: str = "OSINT Platform"
    DEBUG: bool = False
    ENV: str = Field(default="production", pattern="^(development|staging|production)$")

    # -------------------------------------------------------------------------
    # Security
    # -------------------------------------------------------------------------
    SECRET_KEY: str = Field(
        default="change-me-in-production",
        min_length=32,
        description="Secret key for JWT signing. Must be at least 32 characters.",
    )

    # JWT Settings
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, ge=5, le=1440)
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, ge=1, le=30)

    # Password hashing
    BCRYPT_ROUNDS: int = Field(default=12, ge=10, le=14)

    # -------------------------------------------------------------------------
    # Database
    # -------------------------------------------------------------------------
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://osint:osint_secret@localhost:5432/osint_db",
        description="PostgreSQL connection URL with asyncpg driver",
    )

    # Connection pool settings
    DB_POOL_SIZE: int = Field(default=5, ge=1, le=20)
    DB_MAX_OVERFLOW: int = Field(default=10, ge=0, le=20)
    DB_POOL_TIMEOUT: int = Field(default=30, ge=10, le=60)

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        if not v.startswith(("postgresql+asyncpg://", "postgresql://")):
            raise ValueError("DATABASE_URL must be a PostgreSQL connection string")
        # Ensure we're using asyncpg driver
        if v.startswith("postgresql://"):
            v = v.replace("postgresql://", "postgresql+asyncpg://", 1)
        return v

    # -------------------------------------------------------------------------
    # Redis
    # -------------------------------------------------------------------------
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL",
    )

    # -------------------------------------------------------------------------
    # API Server
    # -------------------------------------------------------------------------
    API_HOST: str = "0.0.0.0"
    API_PORT: int = Field(default=8000, ge=1, le=65535)
    API_WORKERS: int = Field(default=4, ge=1, le=16)

    # CORS
    CORS_ORIGINS: str = Field(
        default="http://localhost:3000,http://localhost:5173",
        description="Comma-separated list of allowed origins",
    )

    @property
    def cors_origins_list(self) -> list[str]:
        """Parse CORS origins into a list."""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    # -------------------------------------------------------------------------
    # Rate Limiting
    # -------------------------------------------------------------------------
    RATE_LIMIT_PER_MINUTE: int = Field(default=60, ge=1)
    RATE_LIMIT_PER_HOUR: int = Field(default=1000, ge=1)

    # -------------------------------------------------------------------------
    # Logging
    # -------------------------------------------------------------------------
    LOG_LEVEL: str = Field(
        default="INFO",
        pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$",
    )
    LOG_FORMAT: str = Field(
        default="console",
        pattern="^(console|json)$",
    )

    # -------------------------------------------------------------------------
    # External API Keys (Optional)
    # -------------------------------------------------------------------------
    SHODAN_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    HIBP_API_KEY: Optional[str] = None
    HUNTER_API_KEY: Optional[str] = None
    SECURITYTRAILS_API_KEY: Optional[str] = None
    CENSYS_API_ID: Optional[str] = None
    CENSYS_API_SECRET: Optional[str] = None
    GITHUB_TOKEN: Optional[str] = None

    # -------------------------------------------------------------------------
    # Future Phases (Phase 3+)
    # -------------------------------------------------------------------------
    ELASTICSEARCH_URL: Optional[str] = None
    NEO4J_URI: Optional[str] = None
    NEO4J_USER: Optional[str] = None
    NEO4J_PASSWORD: Optional[str] = None

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------
    def has_api_key(self, service: str) -> bool:
        """Check if an API key is configured for a service."""
        key_name = f"{service.upper()}_API_KEY"
        value = getattr(self, key_name, None)
        return value is not None and len(value) > 0

    def get_api_key(self, service: str) -> Optional[str]:
        """Get an API key by service name."""
        key_name = f"{service.upper()}_API_KEY"
        return getattr(self, key_name, None)

    @property
    def is_development(self) -> bool:
        return self.ENV == "development"

    @property
    def is_production(self) -> bool:
        return self.ENV == "production"


@lru_cache
def get_settings() -> Settings:
    """
    Get cached settings instance.

    Uses lru_cache to ensure settings are only loaded once.
    Call get_settings.cache_clear() to reload settings.
    """
    return Settings()


# Convenience alias
settings = get_settings()
