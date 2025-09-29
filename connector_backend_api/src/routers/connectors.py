from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Path, Query, status
from pydantic import BaseModel, Field

from src.connectors.base import (
    CreateRequest,
    CreateResponse,
    MetadataRequest,
    MetadataResponse,
    SearchRequest,
    SearchResponse,
)
from src.connectors.registry import get_registry

router = APIRouter(prefix="/connectors", tags=["connectors"])


@router.get(
    "",
    summary="List registered connectors",
    description="Returns the list of registered connector keys and their descriptors.",
    response_description="An object containing connector keys and descriptors.",
)
def list_connectors():
    """
    PUBLIC_INTERFACE
    List available connectors.

    Returns:
        JSON with keys and descriptors.
    """
    reg = get_registry()
    return {"keys": reg.list_connectors(), "descriptors": [d.model_dump() for d in reg.descriptors()]}


@router.get(
    "/{provider}/metadata",
    summary="Get connector descriptor/metadata",
    description="Returns the descriptor for a specific provider including capabilities and auth strategies.",
)
def get_connector_metadata(provider: str = Path(..., description="Connector key, e.g. 'jira' or 'confluence'")):
    """
    PUBLIC_INTERFACE
    Return provider descriptor metadata.

    Parameters:
        provider: connector key

    Returns:
        ConnectorDescriptor as JSON.
    """
    reg = get_registry()
    conn = reg.get(provider)
    if not conn:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")
    return conn.descriptor().model_dump()


# Shared request models for top-level search/create proxies

class SearchBody(BaseModel):
    """Body for POST /search proxy to route to provider-specific search."""
    provider: str = Field(..., description="Connector key to route to, e.g., 'jira' or 'confluence'.")
    query: str = Field(..., description="Search query.")
    tenant_id: str = Field(..., description="Tenant performing operation.")
    connection_id: str = Field(..., description="Connection identifier.")
    limit: int = Field(default=20, ge=1, le=100, description="Max results.")
    cursor: Optional[str] = Field(default=None, description="Connector pagination cursor.")
    extra: Dict[str, Any] = Field(default_factory=dict, description="Connector-specific params.")


class CreateBody(BaseModel):
    """Body for POST /create proxy to route to provider-specific create."""
    provider: str = Field(..., description="Connector key to route to.")
    tenant_id: str = Field(..., description="Tenant performing operation.")
    connection_id: str = Field(..., description="Connection identifier.")
    kind: str = Field(..., description="Entity kind (e.g., 'issue', 'page').")
    payload: Dict[str, Any] = Field(..., description="Connector-specific creation payload.")
    extra: Dict[str, Any] = Field(default_factory=dict, description="Connector-specific params.")


@router.post(
    "/search",
    summary="Search via a connector",
    description="Routes a generic search request to the specified provider's search implementation.",
    response_model=SearchResponse,
)
async def proxy_search(body: SearchBody) -> SearchResponse:
    """
    PUBLIC_INTERFACE
    Proxy search to provider.

    Returns:
        SearchResponse
    """
    reg = get_registry()
    conn = reg.get(body.provider)
    if not conn:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")

    req = SearchRequest(
        query=body.query,
        tenant_id=body.tenant_id,
        connection_id=body.connection_id,
        limit=body.limit,
        cursor=body.cursor,
        extra=body.extra,
    )
    return await conn.search(req)


@router.post(
    "/create",
    summary="Create entity via a connector",
    description="Routes a generic create request to the specified provider's create implementation.",
    response_model=CreateResponse,
)
async def proxy_create(body: CreateBody) -> CreateResponse:
    """
    PUBLIC_INTERFACE
    Proxy create to provider.

    Returns:
        CreateResponse
    """
    reg = get_registry()
    conn = reg.get(body.provider)
    if not conn:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")

    req = CreateRequest(
        tenant_id=body.tenant_id,
        connection_id=body.connection_id,
        kind=body.kind,
        payload=body.payload,
        extra=body.extra,
    )
    return await conn.create(req)


@router.get(
    "/{provider}/projects",
    summary="List projects for a provider",
    description="Convenience metadata route to list 'projects' for a provider (e.g., Jira).",
    response_model=MetadataResponse,
)
async def list_projects(
    provider: str = Path(..., description="Connector key."),
    tenant_id: str = Query(..., description="Tenant id."),
    connection_id: str = Query(..., description="Connection id."),
) -> MetadataResponse:
    """
    PUBLIC_INTERFACE
    List projects by delegating to provider metadata(resource='projects').
    """
    reg = get_registry()
    conn = reg.get(provider)
    if not conn:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")

    req = MetadataRequest(tenant_id=tenant_id, connection_id=connection_id, resource="projects", extra={})
    return await conn.metadata(req)


@router.get(
    "/{provider}/spaces",
    summary="List spaces for a provider",
    description="Convenience metadata route to list 'spaces' for a provider (e.g., Confluence).",
    response_model=MetadataResponse,
)
async def list_spaces(
    provider: str = Path(..., description="Connector key."),
    tenant_id: str = Query(..., description="Tenant id."),
    connection_id: str = Query(..., description="Connection id."),
) -> MetadataResponse:
    """
    PUBLIC_INTERFACE
    List spaces by delegating to provider metadata(resource='spaces').
    """
    reg = get_registry()
    conn = reg.get(provider)
    if not conn:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")

    req = MetadataRequest(tenant_id=tenant_id, connection_id=connection_id, resource="spaces", extra={})
    return await conn.metadata(req)


# LLM Tool Proxy Endpoints
# These provide a simple contract for LLM agents to invoke provider tools in a generic way.

class ToolInvokeBody(BaseModel):
    """Body for LLM tool invocation via POST."""
    provider: str = Field(..., description="Connector key.")
    tool: str = Field(..., description="Tool name: 'search', 'create', 'projects', 'spaces'.")
    # Common fields; handler will validate presence as needed
    query: Optional[str] = Field(default=None, description="Search query for 'search' tool.")
    kind: Optional[str] = Field(default=None, description="Entity kind for 'create'.")
    payload: Optional[Dict[str, Any]] = Field(default=None, description="Payload for 'create'.")
    tenant_id: str = Field(..., description="Tenant id.")
    connection_id: str = Field(..., description="Connection id.")
    limit: int = Field(default=20, ge=1, le=100, description="Limit for search.")
    cursor: Optional[str] = Field(default=None, description="Cursor for search pagination.")


@router.get(
    "/tools",
    summary="LLM tool discovery",
    description="Returns a list of available LLM tools and usage notes.",
)
def llm_tools_discovery():
    """
    PUBLIC_INTERFACE
    LLM tools listing and usage notes.
    """
    return {
        "tools": ["search", "create", "projects", "spaces"],
        "usage": {
            "search": "POST /connectors/tools with tool='search', provider, tenant_id, connection_id, query, limit?, cursor?",
            "create": "POST /connectors/tools with tool='create', provider, tenant_id, connection_id, kind, payload",
            "projects": "POST /connectors/tools with tool='projects', provider, tenant_id, connection_id",
            "spaces": "POST /connectors/tools with tool='spaces', provider, tenant_id, connection_id",
        },
    }


@router.post(
    "/tools",
    summary="LLM tool proxy",
    description="Proxy LLM tool invocations to provider operations. Supported tools: search, create, projects, spaces.",
)
async def llm_tool_proxy(body: ToolInvokeBody):
    """
    PUBLIC_INTERFACE
    LLM tool proxy which maps generic tool names to provider operations.
    """
    reg = get_registry()
    conn = reg.get(body.provider)
    if not conn:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")

    tool = body.tool.lower()
    if tool == "search":
        if not body.query:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing 'query' for search tool")
        req = SearchRequest(
            query=body.query,
            tenant_id=body.tenant_id,
            connection_id=body.connection_id,
            limit=body.limit,
            cursor=body.cursor,
            extra={},
        )
        return await conn.search(req)
    elif tool == "create":
        if not body.kind or body.payload is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing 'kind' or 'payload' for create tool")
        req = CreateRequest(
            tenant_id=body.tenant_id,
            connection_id=body.connection_id,
            kind=body.kind,
            payload=body.payload,
            extra={},
        )
        return await conn.create(req)
    elif tool == "projects":
        req = MetadataRequest(tenant_id=body.tenant_id, connection_id=body.connection_id, resource="projects", extra={})
        return await conn.metadata(req)
    elif tool == "spaces":
        req = MetadataRequest(tenant_id=body.tenant_id, connection_id=body.connection_id, resource="spaces", extra={})
        return await conn.metadata(req)
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported tool")
