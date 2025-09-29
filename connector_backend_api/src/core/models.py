"""
Shared Pydantic models for core entities used across the backend.

These include:
- Tenant: represents an organization/workspace
- User: represents an end-user within a tenant
- Connection: a configured connector instance (e.g., Jira, Confluence)
- TokenRecord: secure storage metadata for OAuth tokens or API keys

Note: For persistence with MongoDB, _id fields are represented as str in the API-facing models.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, Literal, Optional

from pydantic import BaseModel, Field


class Tenant(BaseModel):
    """Represents a tenant (organization or workspace)."""

    id: Optional[str] = Field(default=None, description="Unique identifier for the tenant.")
    name: str = Field(..., description="Human-readable tenant name.")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp.")


class User(BaseModel):
    """Represents a user within a tenant."""

    id: Optional[str] = Field(default=None, description="Unique identifier for the user.")
    tenant_id: str = Field(..., description="Tenant identifier.")
    email: str = Field(..., description="User email address.")
    display_name: Optional[str] = Field(default=None, description="Display name for UI.")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp.")


ConnectorType = Literal["jira", "confluence"]


class Connection(BaseModel):
    """Represents a configured connector instance for a tenant."""

    id: Optional[str] = Field(default=None, description="Unique identifier for the connection.")
    tenant_id: str = Field(..., description="Tenant identifier.")
    connector_type: ConnectorType = Field(..., description="Type of connector (e.g., jira, confluence).")
    name: str = Field(..., description="Display name for the connection.")
    # Arbitrary metadata such as base URL, project/space defaults, etc.
    metadata: Dict[str, str] = Field(default_factory=dict, description="Connector-specific metadata.")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp.")
    # status field to enable/disable connection
    enabled: bool = Field(default=True, description="Whether the connection is enabled.")


class TokenRecord(BaseModel):
    """
    Secure storage metadata for connector credentials.

    For OAuth, access/refresh tokens are stored encrypted (AES-GCM envelope JSON).
    For API Key, only a salted hash is stored here; plaintext is never persisted.
    """

    id: Optional[str] = Field(default=None, description="Unique identifier for the token record.")
    tenant_id: str = Field(..., description="Tenant identifier.")
    connection_id: str = Field(..., description="Associated connection identifier.")
    kind: Literal["oauth", "api_key"] = Field(..., description="Type of token record.")
    # For OAuth
    access_token_encrypted: Optional[str] = Field(default=None, description="Encrypted access token (AES-GCM envelope).")
    refresh_token_encrypted: Optional[str] = Field(default=None, description="Encrypted refresh token (AES-GCM envelope).")
    encryption_key_version: Optional[str] = Field(default=None, description="Version label of the key used for encryption.")
    expires_at: Optional[datetime] = Field(default=None, description="Access token expiration (UTC).")
    # For API key
    api_key_hash: Optional[str] = Field(default=None, description="Salted hash of API key.")
    metadata: Dict[str, str] = Field(default_factory=dict, description="Additional metadata such as header_name/prefix.")
    # Bookkeeping
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp.")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Last update timestamp.")
