"""
Base connector interface and shared models for provider implementations (e.g., Jira, Confluence).

This module defines:
- Connector capabilities and descriptors
- Auth configuration models (OAuth/API Key)
- Pydantic request/response models for search/create operations
- A Protocol (BaseConnector) that all connectors should implement

Notes:
- The concrete connectors should use httpx/requests to call external APIs (not implemented here).
- Secrets are not persisted here; see core.security and core.models.TokenRecord for storage metadata.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Iterable, List, Literal, Optional, Protocol, Union

from pydantic import BaseModel, Field, HttpUrl


class AuthStrategy(str, Enum):
    """Supported authentication strategies for connectors."""

    OAUTH = "oauth"
    API_KEY = "api_key"


class Capability(str, Enum):
    """High-level capability flags supported by connectors."""

    SEARCH = "search"
    CREATE = "create"
    METADATA = "metadata"  # e.g., list projects/spaces


class ConnectorDescriptor(BaseModel):
    """Descriptor returned by connectors to advertise their capabilities and metadata."""

    key: str = Field(..., description="Unique connector key, e.g., 'jira', 'confluence'.")
    name: str = Field(..., description="Human-readable connector name.")
    auth_supported: List[AuthStrategy] = Field(..., description="Supported auth strategies.")
    capabilities: List[Capability] = Field(..., description="Supported capabilities.")
    docs_url: Optional[HttpUrl] = Field(default=None, description="Documentation URL for setup.")
    website_url: Optional[HttpUrl] = Field(default=None, description="Vendor website.")
    icon: Optional[str] = Field(default=None, description="Optional icon path or URL for UI.")


# ----- Auth Configuration Models -----


class OAuthConfig(BaseModel):
    """Configuration needed at runtime to perform OAuth on behalf of a tenant/connection."""

    client_id: str = Field(..., description="OAuth client id.")
    client_secret: str = Field(..., description="OAuth client secret.")
    authorize_url: HttpUrl = Field(..., description="Authorization endpoint.")
    token_url: HttpUrl = Field(..., description="Token endpoint.")
    scopes: List[str] = Field(default_factory=list, description="Requested OAuth scopes.")
    redirect_uri: Optional[HttpUrl] = Field(default=None, description="Redirect URI for callbacks; may be computed from SITE_URL.")


class ApiKeyConfig(BaseModel):
    """Configuration for API key-based auth."""

    header_name: str = Field(default="Authorization", description="HTTP header name to carry the API key.")
    prefix: Optional[str] = Field(default=None, description="Optional prefix added before the API key (e.g., 'Bearer').")


AuthConfig = Union[OAuthConfig, ApiKeyConfig]


# ----- Operation Models -----


class SearchRequest(BaseModel):
    """Parameters for a search request to a connector."""

    query: str = Field(..., description="Free-form search query.")
    tenant_id: str = Field(..., description="Tenant performing the search.")
    connection_id: str = Field(..., description="Connection identifier being used.")
    limit: int = Field(default=20, ge=1, le=100, description="Max results to return.")
    cursor: Optional[str] = Field(default=None, description="Opaque cursor for pagination provided by connector.")
    extra: Dict[str, Any] = Field(default_factory=dict, description="Connector-specific parameters.")


class SearchItem(BaseModel):
    """A generic search result item."""

    id: str = Field(..., description="Unique item identifier in the external system.")
    title: str = Field(..., description="Title or summary of the item.")
    url: Optional[HttpUrl] = Field(default=None, description="Deep link to the item.")
    snippet: Optional[str] = Field(default=None, description="Snippet/preview text.")
    icon: Optional[str] = Field(default=None, description="Optional icon URL/path.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Connector-specific metadata payload.")


class SearchResponse(BaseModel):
    """Search response with results and optional pagination cursor."""

    items: List[SearchItem] = Field(default_factory=list, description="List of search result items.")
    next_cursor: Optional[str] = Field(default=None, description="Cursor for fetching the next page (if any).")


class CreateRequest(BaseModel):
    """Create request body for connector entities."""

    tenant_id: str = Field(..., description="Tenant performing the action.")
    connection_id: str = Field(..., description="Connection identifier being used.")
    kind: str = Field(..., description="Entity kind to create (e.g., 'issue', 'page').")
    payload: Dict[str, Any] = Field(..., description="Connector-specific creation payload.")
    extra: Dict[str, Any] = Field(default_factory=dict, description="Connector-specific parameters.")


class CreateResponse(BaseModel):
    """Create response with created entity info."""

    id: str = Field(..., description="Identifier of the created entity in vendor system.")
    url: Optional[HttpUrl] = Field(default=None, description="Deep link to the created entity.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Connector-specific metadata payload.")


class MetadataRequest(BaseModel):
    """Request for metadata listing, such as projects or spaces."""

    tenant_id: str = Field(..., description="Tenant performing the request.")
    connection_id: str = Field(..., description="Connection identifier being used.")
    resource: Literal["projects", "spaces"] = Field(..., description="Resource type to list.")
    extra: Dict[str, Any] = Field(default_factory=dict, description="Connector-specific parameters.")


class MetadataItem(BaseModel):
    """Generic metadata item for lists like projects/spaces."""

    id: str = Field(..., description="Identifier in vendor system.")
    key: Optional[str] = Field(default=None, description="Short key/code (if applicable).")
    name: str = Field(..., description="Display name.")
    url: Optional[HttpUrl] = Field(default=None, description="Deep link to resource.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Connector-specific metadata.")


class MetadataResponse(BaseModel):
    """Response for metadata listing requests."""

    items: List[MetadataItem] = Field(default_factory=list, description="List of items.")


# ----- Base Connector Protocol -----


class BaseConnector(Protocol):
    """
    Interface for connector implementations.

    Concrete connectors should implement interaction methods with their external services.
    """

    # Unique key such as 'jira' or 'confluence'
    key: str
    # Human-friendly display name
    name: str

    # PUBLIC_INTERFACE
    def descriptor(self) -> ConnectorDescriptor:
        """Return a descriptor advertising capabilities and auth support."""
        ...

    # PUBLIC_INTERFACE
    def auth_strategies(self) -> List[AuthStrategy]:
        """Return list of supported authentication strategies."""
        ...

    # PUBLIC_INTERFACE
    async def search(self, req: SearchRequest) -> SearchResponse:
        """Execute a search operation against the vendor system."""
        ...

    # PUBLIC_INTERFACE
    async def create(self, req: CreateRequest) -> CreateResponse:
        """Create an entity in the vendor system."""
        ...

    # PUBLIC_INTERFACE
    async def metadata(self, req: MetadataRequest) -> MetadataResponse:
        """List metadata resources such as projects/spaces."""
        ...

    # PUBLIC_INTERFACE
    def apply_auth(self, headers: Dict[str, str], *, auth: Dict[str, Any]) -> Dict[str, str]:
        """
        Apply authentication information to HTTP headers.

        'auth' may contain:
        - For OAuth: {'kind': 'oauth', 'access_token': '...'}
        - For API Key: {'kind': 'api_key', 'api_key': '...', 'header_name'?: '...', 'prefix'?: 'Bearer'}

        Returns headers including necessary auth info.
        """
        ...

    # PUBLIC_INTERFACE
    def default_headers(self) -> Dict[str, str]:
        """Return default headers to use for HTTP calls (e.g., JSON content-type)."""
        return {"Accept": "application/json", "Content-Type": "application/json"}

    # PUBLIC_INTERFACE
    def base_url_from_metadata(self, metadata: Dict[str, Any]) -> Optional[str]:
        """Get base URL to call for the connector from stored connection metadata, if applicable."""
        return metadata.get("base_url") if metadata else None


# Utility helpers (non-protocol)


def ensure_prefix(value: str, prefix: Optional[str]) -> str:
    """Ensure the header value is correctly prefixed when prefix is provided."""
    return f"{prefix} {value}" if prefix else value


def merge_headers(*parts: Iterable[Dict[str, str]]) -> Dict[str, str]:
    """Merge multiple header dicts; later dicts override earlier ones."""
    merged: Dict[str, str] = {}
    for p in parts:
        merged.update(p)
    return merged
