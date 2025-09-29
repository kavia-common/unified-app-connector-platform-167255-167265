"""
Core configuration module for the backend service.

Loads environment variables using Pydantic BaseSettings to provide a
strongly-typed configuration for the application.

This module centralizes configuration for:
- Application metadata
- CORS and environment
- MongoDB (async, Motor)
- Security (JWT for OAuth state, API key hashing)
- Multi-tenancy (tenant ID headers and defaults)

Note: All secrets and environment-specific values must be set via environment
variables (see .env.example). Never hardcode secret values in source code.
"""

from functools import lru_cache
from typing import List, Optional

from pydantic import AnyUrl, Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # App metadata for OpenAPI docs
    APP_NAME: str = Field(default="Connector Backend API", description="Application name.")
    APP_DESCRIPTION: str = Field(
        default="Backend service managing connectors, authentication (OAuth/API Key), multi-tenant logic, and business logic for interacting with third-party APIs such as Jira and Confluence.",
        description="Application description shown in OpenAPI.",
    )
    APP_VERSION: str = Field(default="0.1.0", description="Application version.")
    ENVIRONMENT: str = Field(default="development", description="Environment name (development/staging/production).")

    # CORS
    CORS_ALLOW_ORIGINS: List[str] = Field(
        default=["*"],
        description="Allowed origins for CORS.",
    )
    CORS_ALLOW_CREDENTIALS: bool = Field(default=True, description="Allow credentials for CORS.")
    CORS_ALLOW_METHODS: List[str] = Field(default=["*"], description="Allowed methods for CORS.")
    CORS_ALLOW_HEADERS: List[str] = Field(default=["*"], description="Allowed headers for CORS.")

    # MongoDB (Motor async)
    MONGODB_URI: str = Field(
        default="mongodb://localhost:27017",
        description="MongoDB connection URI for Motor client.",
    )
    MONGODB_DB_NAME: str = Field(default="connector_platform", description="MongoDB database name.")

    # Security - JWT used for state param in OAuth flows
    JWT_ALGORITHM: str = Field(default="HS256", description="JWT signing algorithm.")
    JWT_STATE_SECRET: str = Field(default="CHANGE_ME", description="Secret for signing OAuth state JWTs.")
    JWT_STATE_TTL_SECONDS: int = Field(default=600, description="TTL for OAuth state (seconds).")

    # Security - API key hashing
    API_KEY_HASH_SALT: str = Field(default="CHANGE_ME_SALT", description="Salt for API key hashing.")
    API_KEY_HASH_ALGORITHM: str = Field(default="sha256", description="Algorithm for API key hashing.")

    # Encryption for stored credentials (AES-GCM)
    ENCRYPTION_KEY: str = Field(
        default="",
        description="Base64-encoded 32-byte key (AES-256) used for AES-GCM encryption. Do NOT hardcode in prod.",
    )
    ENCRYPTION_KEY_VERSION: str = Field(
        default="v1",
        description="Current active encryption key version label. Used for key rotation.",
    )

    # Multi-tenant behavior
    TENANT_HEADER_NAME: str = Field(default="X-Tenant-ID", description="Header used to pass Tenant ID.")
    DEFAULT_TENANT_ID: Optional[str] = Field(default=None, description="Optional default tenant for dev/testing.")

    # Site URL for redirects (used later by OAuth flows)
    SITE_URL: Optional[AnyUrl] = Field(default=None, description="Public site URL for redirects.")

    class Config:
        env_file = ".env"
        case_sensitive = True


# PUBLIC_INTERFACE
def get_settings() -> Settings:
    """
    Returns the singleton Settings instance loaded from environment variables.

    This function is memoized to avoid repeated parsing of environment variables.
    """
    return _get_settings()


@lru_cache(maxsize=1)
def _get_settings() -> Settings:
    return Settings()
