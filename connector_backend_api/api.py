"""
FastAPI routers for the Connector Backend API.

Includes:
- Auth endpoints (/auth/api-key, /auth/oauth) for token storage/validation
- Connector registry endpoints
- Business endpoints: /search, /create, /projects, /spaces
- LLM proxy endpoint (/llm-proxy)
- Standardized response format and error taxonomy
- Rate limit enforcement and retry/backoff for external calls

This module wires routers; main.py should include app.include_router(api_router).

Environment variables needed (set via orchestrator in .env):
- MONGODB_URI
- MONGODB_DB
- ENCRYPTION_KEY (optional; for token encryption)
- OAUTH_REDIRECT_BASE_URL (for oauth callback composition)
- LLM_PROXY_URL (optional; base url to forward to LLM service)
- LLM_PROXY_KEY (optional; auth key for LLM proxy)
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from .models.connector import ConnectorRepo, Connector
from .models.rate_limit import RateLimitRepo
from .models.tenant import TenantRepo
from .models.user_token import UserTokenRepo, UserToken
from .services.connectors import (
    JiraConnectorService,
    ConfluenceConnectorService,
    ProviderServiceBase,
    get_provider_service,
)
from .utils.auth import (
    TenantContext,
    get_tenant_context,
    require_authenticated_connector,
)
from .utils.errors import (
    ApiError,
    ErrorCode,
    api_error_response,
    standard_response,
)
from .utils.limiter import rate_limit_guard
from .utils.retry import retry_async


# ---------- Pydantic Schemas ----------


class ApiKeyAuthRequest(BaseModel):
    connector_key: str = Field(..., description="Connector key, e.g., 'jira' or 'confluence'")
    api_key: str = Field(..., description="API key/token")
    user_id: str = Field(..., description="User id within the tenant")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Optional provider metadata")


class OAuthStartRequest(BaseModel):
    connector_key: str = Field(..., description="Connector key")
    user_id: str = Field(..., description="User id within the tenant")
    state: Optional[str] = Field(None, description="Opaque state to return after callback")
    scopes: Optional[List[str]] = Field(None, description="Requested scopes")


class OAuthStartResponse(BaseModel):
    auth_url: str = Field(..., description="URL to redirect user to start OAuth")


class OAuthCallbackRequest(BaseModel):
    connector_key: str = Field(..., description="Connector key")
    user_id: str = Field(..., description="User id within tenant")
    code: str = Field(..., description="Authorization code from provider")
    state: Optional[str] = Field(None, description="Opaque state value")


class SearchRequest(BaseModel):
    connector_key: str = Field(..., description="Connector key to search")
    user_id: str = Field(..., description="User id performing the search")
    query: str = Field(..., description="Free text query")
    filters: Optional[Dict[str, Any]] = Field(None, description="Provider-specific filters")
    limit: int = Field(10, description="Max results", ge=1, le=50)


class SearchItem(BaseModel):
    id: str = Field(..., description="Result id")
    title: str = Field(..., description="Primary title")
    url: Optional[str] = Field(None, description="URL to open")
    snippet: Optional[str] = Field(None, description="Snippet/preview")
    meta: Optional[Dict[str, Any]] = Field(None, description="Additional fields")


class CreateRequest(BaseModel):
    connector_key: str = Field(..., description="Connector key")
    user_id: str = Field(..., description="User id performing the create")
    payload: Dict[str, Any] = Field(..., description="Provider-specific create payload")


class CreateResponse(BaseModel):
    id: str = Field(..., description="Created object id")
    url: Optional[str] = Field(None, description="URL to open")
    meta: Optional[Dict[str, Any]] = Field(None, description="Additional fields")


class ProjectsResponse(BaseModel):
    projects: List[Dict[str, Any]] = Field(..., description="List of projects/spaces metadata")


class SpacesResponse(BaseModel):
    spaces: List[Dict[str, Any]] = Field(..., description="List of spaces metadata")


class ConnectorUpsertRequest(BaseModel):
    key: str = Field(..., description="Connector key")
    display_name: str = Field(..., description="UI display name")
    provider: str = Field(..., description="Provider label, e.g., 'atlassian'")
    auth_type: str = Field("oauth", description="oauth | api_key | none")
    enabled: bool = Field(True, description="Whether connector is enabled")
    operations: Optional[Dict[str, bool]] = Field(None, description="Capability flags")
    settings: Optional[Dict[str, Any]] = Field(None, description="Provider settings")
    client_id: Optional[str] = Field(None, description="OAuth client id")
    client_secret: Optional[str] = Field(None, description="OAuth client secret")


class ConnectorResponse(BaseModel):
    key: str
    display_name: str
    provider: str
    enabled: bool
    auth_type: str
    operations: Dict[str, bool]
    settings: Dict[str, Any]


# ---------- Router setup ----------

api_router = APIRouter()


# ---------- Helper mappers ----------


def connector_to_response(c: Connector) -> ConnectorResponse:
    return ConnectorResponse(
        key=c.key,
        display_name=c.display_name,
        provider=c.provider,
        enabled=c.enabled,
        auth_type=c.auth_type,
        operations=c.operations,
        settings=c.settings,
    )


# ---------- Auth Endpoints ----------


@api_router.post(
    "/auth/api-key",
    tags=["auth"],
    summary="Store/validate API key for a connector",
    description="Validates provided API key with provider and stores per user/tenant",
)
async def auth_api_key(
    body: ApiKeyAuthRequest,
    ctx: TenantContext = Depends(get_tenant_context),
):
    """
    PUBLIC_INTERFACE
    Validates API key against provider and stores securely. Returns standardized success payload.
    """
    connector_repo = ConnectorRepo()
    token_repo = UserTokenRepo()

    connector = await connector_repo.find_one({"tenant_id": ctx.tenant_id, "key": body.connector_key})
    if not connector or not connector.enabled:
        raise api_error_response(ErrorCode.CONNECTOR_NOT_FOUND, "Connector not available")

    service = get_provider_service(connector.key, connector.provider, ctx, token_repo)
    ok, meta = await service.validate_api_key(body.api_key)
    if not ok:
        raise api_error_response(ErrorCode.AUTH_INVALID, "API key invalid")

    saved = await token_repo.upsert_token(
        tenant_id=ctx.tenant_id,
        user_id=body.user_id,
        connector_key=body.connector_key,
        data={"api_key": body.api_key, "metadata": {**(body.metadata or {}), **(meta or {})}},
    )
    return standard_response({"connected": True, "connector_key": body.connector_key, "user_id": saved.user_id})


@api_router.post(
    "/auth/oauth/start",
    tags=["auth"],
    summary="Start OAuth flow",
    description="Returns provider authorization URL to redirect user.",
    response_model=Dict[str, str],
)
async def auth_oauth_start(body: OAuthStartRequest, ctx: TenantContext = Depends(get_tenant_context)):
    """
    PUBLIC_INTERFACE
    Returns OAuth authorization URL for the provider. The caller should redirect the user to this URL.
    """
    connector_repo = ConnectorRepo()
    connector = await connector_repo.find_one({"tenant_id": ctx.tenant_id, "key": body.connector_key})
    if not connector or not connector.enabled or connector.auth_type != "oauth":
        raise api_error_response(ErrorCode.CONNECTOR_NOT_FOUND, "Connector not available or not oauth")

    token_repo = UserTokenRepo()
    service = get_provider_service(connector.key, connector.provider, ctx, token_repo)
    url = await service.oauth_authorization_url(user_id=body.user_id, scopes=body.scopes, state=body.state)
    return standard_response({"auth_url": url})


@api_router.post(
    "/auth/oauth/callback",
    tags=["auth"],
    summary="Handle OAuth callback",
    description="Exchanges code for tokens and stores them securely.",
)
async def auth_oauth_callback(body: OAuthCallbackRequest, ctx: TenantContext = Depends(get_tenant_context)):
    """
    PUBLIC_INTERFACE
    OAuth callback handler. Exchanges the authorization code for tokens and persists them for the user.
    """
    connector_repo = ConnectorRepo()
    token_repo = UserTokenRepo()

    connector = await connector_repo.find_one({"tenant_id": ctx.tenant_id, "key": body.connector_key})
    if not connector or not connector.enabled or connector.auth_type != "oauth":
        raise api_error_response(ErrorCode.CONNECTOR_NOT_FOUND, "Connector not available or not oauth")

    service = get_provider_service(connector.key, connector.provider, ctx, token_repo)
    try:
        await service.exchange_code_and_store_tokens(user_id=body.user_id, code=body.code, state=body.state)
    except ApiError as e:
        raise api_error_response(e.code, e.message)

    return standard_response({"connected": True, "connector_key": body.connector_key, "user_id": body.user_id})


# ---------- Registry Endpoints ----------


@api_router.get(
    "/connectors",
    tags=["connectors"],
    summary="List connectors for tenant",
    description="Returns registered connectors for the active tenant",
)
async def list_connectors(ctx: TenantContext = Depends(get_tenant_context)):
    """
    PUBLIC_INTERFACE
    List all connectors for tenant.
    """
    items = await ConnectorRepo().find({"tenant_id": ctx.tenant_id})
    return standard_response({"items": [connector_to_response(c).model_dump() for c in items]})


@api_router.post(
    "/connectors/{key}",
    tags=["connectors"],
    summary="Create or update connector config",
    description="Upsert a connector entry for the tenant",
)
async def upsert_connector(
    key: str,
    body: ConnectorUpsertRequest,
    ctx: TenantContext = Depends(get_tenant_context),
):
    """
    PUBLIC_INTERFACE
    Upsert a connector config for the tenant.
    """
    if key != body.key:
        raise api_error_response(ErrorCode.BAD_REQUEST, "Path key and body key mismatch")

    repo = ConnectorRepo()
    saved = await repo.upsert_connector(
        tenant_id=ctx.tenant_id,
        key=key,
        data={
            "display_name": body.display_name,
            "provider": body.provider,
            "auth_type": body.auth_type,
            "enabled": body.enabled,
            "operations": body.operations or {
                "search": True,
                "create": False,
                "update": False,
                "delete": False,
                "list_projects": True,
            },
            "settings": body.settings or {},
            "client_id": body.client_id,
            "client_secret": body.client_secret,
        },
    )
    return standard_response({"item": connector_to_response(saved).model_dump()})


# ---------- Business Endpoints ----------


@api_router.post(
    "/search",
    tags=["operations"],
    summary="Search in a connector",
    description="Search across a provider using configured credentials",
)
async def search(
    body: SearchRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    _auth=Depends(require_authenticated_connector),
):
    """
    PUBLIC_INTERFACE
    Execute a search against the provider with retries and rate limiting.
    """
    # Rate limit guard
    await rate_limit_guard(ctx.tenant_id, body.connector_key, user_id=body.user_id)

    token_repo = UserTokenRepo()
    service = await _get_service_for_op(body.connector_key, ctx, token_repo)

    async def _op():
        results = await service.search(user_id=body.user_id, query=body.query, filters=body.filters, limit=body.limit)
        return results

    results = await retry_async(_op)
    return standard_response({"items": [SearchItem(**r).model_dump() for r in results]})


@api_router.post(
    "/create",
    tags=["operations"],
    summary="Create an item in provider",
    description="Creates an item (e.g., Jira issue, Confluence page)",
)
async def create(
    body: CreateRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    _auth=Depends(require_authenticated_connector),
):
    """
    PUBLIC_INTERFACE
    Create an item within the provider with retries and rate limiting.
    """
    await rate_limit_guard(ctx.tenant_id, body.connector_key, user_id=body.user_id)

    token_repo = UserTokenRepo()
    service = await _get_service_for_op(body.connector_key, ctx, token_repo)

    async def _op():
        res = await service.create(user_id=body.user_id, payload=body.payload)
        return res

    created = await retry_async(_op)
    return standard_response(CreateResponse(**created).model_dump())


@api_router.get(
    "/projects",
    tags=["operations"],
    summary="List projects",
    description="Lists projects for connectors supporting project listing (e.g., Jira)",
)
async def list_projects(
    connector_key: str,
    user_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    _auth=Depends(require_authenticated_connector),
):
    """
    PUBLIC_INTERFACE
    List projects for the given connector.
    """
    await rate_limit_guard(ctx.tenant_id, connector_key, user_id=user_id)
    token_repo = UserTokenRepo()
    service = await _get_service_for_op(connector_key, ctx, token_repo)
    items = await retry_async(lambda: service.list_projects(user_id=user_id))
    return standard_response(ProjectsResponse(projects=items).model_dump())


@api_router.get(
    "/spaces",
    tags=["operations"],
    summary="List spaces",
    description="Lists spaces for connectors supporting spaces (e.g., Confluence)",
)
async def list_spaces(
    connector_key: str,
    user_id: str,
    ctx: TenantContext = Depends(get_tenant_context),
    _auth=Depends(require_authenticated_connector),
):
    """
    PUBLIC_INTERFACE
    List spaces for the given connector.
    """
    await rate_limit_guard(ctx.tenant_id, connector_key, user_id=user_id)
    token_repo = UserTokenRepo()
    service = await _get_service_for_op(connector_key, ctx, token_repo)
    items = await retry_async(lambda: service.list_spaces(user_id=user_id))
    return standard_response(SpacesResponse(spaces=items).model_dump())


# ---------- LLM Proxy ----------


@api_router.post(
    "/llm-proxy",
    tags=["ai"],
    summary="Proxy requests to LLM service",
    description="Forwards payloads to configured LLM service with retries and unified error handling.",
)
async def llm_proxy(request: Request, ctx: TenantContext = Depends(get_tenant_context)):
    """
    PUBLIC_INTERFACE
    Proxies request body to LLM service using configured environment variables.
    """
    import os

    base_url = os.getenv("LLM_PROXY_URL")
    api_key = os.getenv("LLM_PROXY_KEY")
    if not base_url:
        raise api_error_response(ErrorCode.BAD_GATEWAY, "LLM proxy not configured")

    payload = await request.json()
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    async def _op():
        async with httpx.AsyncClient(timeout=20.0) as client:
            res = await client.post(base_url, json=payload, headers=headers)
            if res.status_code >= 400:
                raise ApiError(ErrorCode.BAD_GATEWAY, f"LLM proxy error {res.status_code}: {res.text}")
            return res.json()

    data = await retry_async(_op)
    return standard_response({"data": data})


# ---------- Helpers ----------


async def _get_service_for_op(
    connector_key: str, ctx: TenantContext, token_repo: UserTokenRepo
) -> ProviderServiceBase:
    connector = await ConnectorRepo().find_one({"tenant_id": ctx.tenant_id, "key": connector_key})
    if not connector or not connector.enabled:
        raise api_error_response(ErrorCode.CONNECTOR_NOT_FOUND, "Connector not available")
    return get_provider_service(connector.key, connector.provider, ctx, token_repo)
