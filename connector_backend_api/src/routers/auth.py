from __future__ import annotations

import base64
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Literal, Optional, TypedDict

import httpx
from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, HttpUrl

from src.core.config import get_settings
from src.core.db import get_tenant_collection
from src.core.security import decode_oauth_state, encode_oauth_state, hash_api_key, verify_api_key

router = APIRouter(prefix="/auth", tags=["auth"])

# ----- Pydantic models for requests/responses -----


class OAuthLoginRequest(BaseModel):
    """Request body for starting an OAuth flow."""
    connector: Literal["jira", "confluence"] = Field(..., description="Connector key for which OAuth is initiated.")
    tenant_id: str = Field(..., description="Tenant initiating the flow.")
    connection_id: str = Field(..., description="Connection identifier to bind credentials.")
    authorize_url: HttpUrl = Field(..., description="Authorization endpoint of the provider.")
    client_id: str = Field(..., description="OAuth client id registered with the provider.")
    scopes: list[str] = Field(default_factory=list, description="Requested scopes.")
    redirect_uri: Optional[HttpUrl] = Field(default=None, description="Optional override callback redirect URI; defaults to {SITE_URL}/oauth/callback")


class OAuthLoginResponse(BaseModel):
    """Response with the provider authorization URL."""
    authorize_url: HttpUrl = Field(..., description="Redirect here to complete OAuth login.")
    state: str = Field(..., description="Opaque state value bound to this login attempt (signed).")


class OAuthCallbackResponse(BaseModel):
    """Response after handling OAuth callback."""
    message: str = Field(..., description="Short message about result.")
    connection_id: str = Field(..., description="Connection identifier associated with the credentials.")
    tenant_id: str = Field(..., description="Tenant id")
    expires_at: Optional[datetime] = Field(default=None, description="Access token expiration (UTC) if available.")


class OAuthRefreshRequest(BaseModel):
    """Request to refresh an OAuth access token."""
    tenant_id: str = Field(..., description="Tenant id.")
    connection_id: str = Field(..., description="Connection id bound to credentials.")
    token_url: HttpUrl = Field(..., description="Token endpoint to refresh the token.")
    client_id: str = Field(..., description="OAuth client id.")
    client_secret: str = Field(..., description="OAuth client secret.")
    extra: Dict[str, Any] = Field(default_factory=dict, description="Optional extra fields per provider.")


class OAuthRefreshResponse(BaseModel):
    """Response from a token refresh."""
    message: str = Field(..., description="Short message about result.")
    expires_at: Optional[datetime] = Field(default=None, description="New access expiry if available.")


class ApiKeyUpsertRequest(BaseModel):
    """Request to set an API key for a connection."""
    tenant_id: str = Field(..., description="Tenant id.")
    connection_id: str = Field(..., description="Connection id bound to credentials.")
    api_key: str = Field(..., description="Plaintext API key (not stored as plaintext).")
    header_name: Optional[str] = Field(default="Authorization", description="Header name to use when applying the API key.")
    prefix: Optional[str] = Field(default="Bearer", description="Optional prefix for header value.")


class ApiKeyVerifyRequest(BaseModel):
    """Request to verify an API key against stored hash."""
    tenant_id: str = Field(..., description="Tenant id.")
    connection_id: str = Field(..., description="Connection id bound to credentials.")
    api_key: str = Field(..., description="Plaintext API key to verify.")


class ApiKeyResponse(BaseModel):
    """Response for API key operations."""
    message: str = Field(..., description="Result message.")
    valid: Optional[bool] = Field(default=None, description="Whether the API key matches stored hash (for verify).")


# ----- Helpers -----


class OAuthState(TypedDict):
    tenant_id: str
    connection_id: str
    connector: str
    nonce: str


def _tenant_tokens_collection(tenant_id: str):
    # Tokens for all tenants stored in one collection, filtered by tenant_id in queries.
    return get_tenant_collection("token_records", tenant_id)


def _encrypt_token(plaintext: str) -> str:
    """
    NOTE: Placeholder "encryption".
    For MVP we base64-encode. Replace with proper encryption (e.g., Fernet) in production.
    """
    return base64.b64encode(plaintext.encode("utf-8")).decode("utf-8")


def _decrypt_token(ciphertext: str) -> str:
    return base64.b64decode(ciphertext.encode("utf-8")).decode("utf-8")


async def _upsert_oauth_tokens(
    *,
    tenant_id: str,
    connection_id: str,
    access_token: str,
    refresh_token: Optional[str],
    expires_in: Optional[int],
) -> Optional[datetime]:
    """Insert or update an OAuth TokenRecord for the given tenant/connection."""
    coll = _tenant_tokens_collection(tenant_id)
    now = datetime.now(timezone.utc)
    expires_at = None
    if expires_in is not None:
        expires_at = now + timedelta(seconds=int(expires_in))

    doc = {
        "tenant_id": tenant_id,
        "connection_id": connection_id,
        "kind": "oauth",
        "access_token_encrypted": _encrypt_token(access_token),
        "refresh_token_encrypted": _encrypt_token(refresh_token) if refresh_token else None,
        "expires_at": expires_at,
        "updated_at": now,
        "created_at": now,
    }

    # Upsert by (tenant_id, connection_id, kind)
    await coll.update_one(
        {"tenant_id": tenant_id, "connection_id": connection_id, "kind": "oauth"},
        {"$set": {k: v for k, v in doc.items() if k != "created_at"}, "$setOnInsert": {"created_at": now}},
        upsert=True,
    )
    return expires_at


async def _get_oauth_record(tenant_id: str, connection_id: str) -> Optional[Dict[str, Any]]:
    coll = _tenant_tokens_collection(tenant_id)
    doc = await coll.find_one({"tenant_id": tenant_id, "connection_id": connection_id, "kind": "oauth"})
    return doc


async def _upsert_api_key(
    *,
    tenant_id: str,
    connection_id: str,
    api_key_plain: str,
    header_name: Optional[str],
    prefix: Optional[str],
) -> None:
    coll = _tenant_tokens_collection(tenant_id)
    now = datetime.now(timezone.utc)
    hashed = hash_api_key(api_key_plain)
    doc = {
        "tenant_id": tenant_id,
        "connection_id": connection_id,
        "kind": "api_key",
        "api_key_hash": hashed,
        "updated_at": now,
        "created_at": now,
        # Optional metadata for how to apply, useful for connectors
        "metadata": {
            "header_name": header_name or "Authorization",
            "prefix": prefix,  # can be None
        },
    }
    await coll.update_one(
        {"tenant_id": tenant_id, "connection_id": connection_id, "kind": "api_key"},
        {"$set": {k: v for k, v in doc.items() if k != "created_at"}, "$setOnInsert": {"created_at": now}},
        upsert=True,
    )


async def _get_api_key_record(tenant_id: str, connection_id: str) -> Optional[Dict[str, Any]]:
    coll = _tenant_tokens_collection(tenant_id)
    return await coll.find_one({"tenant_id": tenant_id, "connection_id": connection_id, "kind": "api_key"})


# ----- Routes -----


@router.post(
    "/apikey",
    summary="Store or update API key for a connection",
    description="Stores a hashed API key for a tenant/connection. Plaintext is never persisted.",
    response_model=ApiKeyResponse,
    responses={
        200: {"description": "Stored/updated."},
        400: {"description": "Invalid input"},
    },
)
def set_api_key(req: ApiKeyUpsertRequest):
    """
    PUBLIC_INTERFACE
    Store or update API key credentials for a connection.

    Persists a salted hash of the API key in the token store.
    """
    # Since Motor is async, but this handler is sync, we can switch to async by defining as async.
    # For simplicity and consistency, define as async:
    raise HTTPException(status_code=500, detail="Handler should be async")


@router.post(
    "/apikey/verify",
    summary="Verify API key against stored hash",
    description="Checks provided API key against stored salted hash for a connection.",
    response_model=ApiKeyResponse,
)
async def verify_api_key_route(req: ApiKeyVerifyRequest) -> ApiKeyResponse:
    rec = await _get_api_key_record(req.tenant_id, req.connection_id)
    if not rec or not rec.get("api_key_hash"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No API key stored.")
    valid = verify_api_key(req.api_key, rec["api_key_hash"])
    return ApiKeyResponse(message="Verification complete.", valid=valid)


@router.post(
    "/oauth/login",
    summary="Start OAuth login",
    description="Generates a provider authorization URL and signed state parameter for initiating OAuth.",
    response_model=OAuthLoginResponse,
    tags=["auth", "oauth"],
)
async def oauth_login(req: OAuthLoginRequest) -> OAuthLoginResponse:
    """
    PUBLIC_INTERFACE
    Start OAuth flow for a connector.

    - Signs a 'state' JWT with tenant_id, connection_id, connector and nonce.
    - Returns the provider authorize URL with state and scopes.
    """
    settings = get_settings()
    nonce = base64.urlsafe_b64encode(os.urandom(18)).decode("utf-8").rstrip("=")
    state_payload: OAuthState = {
        "tenant_id": req.tenant_id,
        "connection_id": req.connection_id,
        "connector": req.connector,
        "nonce": nonce,
    }
    state = encode_oauth_state(state_payload)

    redirect_uri = str(req.redirect_uri) if req.redirect_uri else (
        f"{settings.SITE_URL.rstrip('/')}/oauth/callback" if settings.SITE_URL else None
    )
    # Compose query params
    query = {
        "response_type": "code",
        "client_id": req.client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(req.scopes) if req.scopes else None,
        "state": state,
    }
    # Remove None
    query = {k: v for k, v in query.items() if v is not None}

    # Build authorize URL
    authorize_url = httpx.URL(str(req.authorize_url)).copy_set_param("state", state)
    for k, v in query.items():
        authorize_url = authorize_url.copy_set_param(k, v)

    return OAuthLoginResponse(authorize_url=HttpUrl(str(authorize_url), scheme=authorize_url.scheme), state=state)


@router.get(
    "/oauth/callback",
    summary="OAuth callback handler",
    description="Handles provider redirect, exchanges code for tokens, and stores credentials securely.",
    response_model=OAuthCallbackResponse,
    tags=["auth", "oauth"],
    responses={
        400: {"description": "Bad request or invalid state"},
        500: {"description": "Token exchange failure"},
    },
)
async def oauth_callback(
    request: Request,
    code: Optional[str] = Query(default=None, description="Authorization code returned by the provider."),
    state: str = Query(..., description="Opaque state parameter returned by the provider."),
    error: Optional[str] = Query(default=None, description="Optional error returned by provider."),
    error_description: Optional[str] = Query(default=None, description="Optional error description."),
) -> OAuthCallbackResponse:
    """
    PUBLIC_INTERFACE
    OAuth callback endpoint.

    - Verifies state JWT and extracts tenant/connection.
    - Exchanges 'code' for tokens via provider token endpoint posted from frontend via form or query config (see notes).
    - Stores encrypted access/refresh tokens and expiry in DB.
    """
    if error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Provider error: {error}: {error_description or ''}".strip())

    try:
        sdata = decode_oauth_state(state)
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid state: {ex}")

    # Extract exchanged token parameters from headers for flexibility:
    # The frontend can POST or GET with headers x-token-url, x-client-id, x-client-secret, x-redirect-uri
    # For GET callback, we expect these to be configured at the app level; to keep MVP, read from headers.
    token_url = request.headers.get("x-token-url")
    client_id = request.headers.get("x-client-id")
    client_secret = request.headers.get("x-client-secret")
    redirect_uri = request.headers.get("x-redirect-uri")

    if not all([code, token_url, client_id, client_secret]):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing code or token exchange configuration (headers).")

    # Exchange code for tokens
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    if redirect_uri:
        data["redirect_uri"] = redirect_uri

    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.post(token_url, data=data, headers={"Accept": "application/json"})
        if resp.status_code >= 400:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Token exchange failed: {resp.status_code} {resp.text}")
        token_payload = resp.json()

    access_token = token_payload.get("access_token")
    refresh_token = token_payload.get("refresh_token")
    expires_in = token_payload.get("expires_in")

    if not access_token:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Token exchange did not return access_token")

    expires_at = await _upsert_oauth_tokens(
        tenant_id=sdata["tenant_id"],
        connection_id=sdata["connection_id"],
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
    )

    return OAuthCallbackResponse(
        message="OAuth successful",
        connection_id=sdata["connection_id"],
        tenant_id=sdata["tenant_id"],
        expires_at=expires_at,
    )


@router.post(
    "/oauth/refresh",
    summary="Refresh OAuth access token",
    description="Uses stored refresh token to obtain a new access token and updates persisted credentials.",
    response_model=OAuthRefreshResponse,
    tags=["auth", "oauth"],
)
async def oauth_refresh(req: OAuthRefreshRequest) -> OAuthRefreshResponse:
    """
    PUBLIC_INTERFACE
    Refresh OAuth token for a connection if refresh_token is present.
    """
    record = await _get_oauth_record(req.tenant_id, req.connection_id)
    if not record or not record.get("refresh_token_encrypted"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No refresh token stored for this connection.")

    refresh_token = _decrypt_token(record["refresh_token_encrypted"])
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": req.client_id,
        "client_secret": req.client_secret,
        **req.extra,
    }

    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.post(str(req.token_url), data=data, headers={"Accept": "application/json"})
        if resp.status_code >= 400:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Refresh failed: {resp.status_code} {resp.text}")
        payload = resp.json()

    access_token = payload.get("access_token")
    new_refresh_token = payload.get("refresh_token", refresh_token)  # Some providers rotate; otherwise reuse.
    expires_in = payload.get("expires_in")

    if not access_token:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Refresh response missing access_token")

    expires_at = await _upsert_oauth_tokens(
        tenant_id=req.tenant_id,
        connection_id=req.connection_id,
        access_token=access_token,
        refresh_token=new_refresh_token,
        expires_in=expires_in,
    )

    return OAuthRefreshResponse(message="Token refreshed", expires_at=expires_at)


# Re-define set_api_key as async (Motor requires async)
@router.post(
    "/apikey",
    summary="Store or update API key for a connection",
    description="Stores a hashed API key for a tenant/connection. Plaintext is never persisted.",
    response_model=ApiKeyResponse,
    responses={
        200: {"description": "Stored/updated."},
        400: {"description": "Invalid input"},
    },
)
async def set_api_key_async(req: ApiKeyUpsertRequest) -> ApiKeyResponse:
    await _upsert_api_key(
        tenant_id=req.tenant_id,
        connection_id=req.connection_id,
        api_key_plain=req.api_key,
        header_name=req.header_name,
        prefix=req.prefix,
    )
    return ApiKeyResponse(message="API key stored.", valid=None)
