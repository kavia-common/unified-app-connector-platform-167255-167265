"""
Tenant context extraction, authorization enforcement, and audit logging.

This module provides:
- TenantContext: holds per-request tenant/user metadata parsed from headers/JWT
- Dependencies to extract and enforce tenant on routes
- Authorization utilities to verify that a request can act on a given tenant/connection
- Audit logging helpers that persist audit events to MongoDB

Notes:
- JWT verification for application auth is kept minimal for MVP. Extend to use real issuer/audience/keys as needed.
- Audit logs are written best-effort and should never block a successful user operation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

import jwt
from fastapi import Header, HTTPException, Request, status
from pydantic import BaseModel, Field

from src.core.config import get_settings
from src.core.db import get_tenant_collection


class TenantContext(BaseModel):
    """Holds request-scoped tenant and user identification."""
    tenant_id: str = Field(..., description="Tenant identifier for this request.")
    user_id: Optional[str] = Field(default=None, description="End user id if provided by auth.")
    email: Optional[str] = Field(default=None, description="End user email if available.")
    roles: list[str] = Field(default_factory=list, description="Role claims for authorization.")
    jwt_sub: Optional[str] = Field(default=None, description="Raw JWT subject value when using JWT.")

    # PUBLIC_INTERFACE
    def can_access_tenant(self, tenant_id: str) -> bool:
        """Simple check: the provided tenant_id must match the context tenant."""
        return self.tenant_id == tenant_id

    # PUBLIC_INTERFACE
    def is_admin(self) -> bool:
        """Return True if user has 'admin' role within this tenant."""
        return "admin" in {r.lower() for r in self.roles}


# PUBLIC_INTERFACE
async def get_tenant_context(
    request: Request,
    x_tenant_id: Optional[str] = Header(default=None, alias=None),
    authorization: Optional[str] = Header(default=None),
) -> TenantContext:
    """
    Resolve TenantContext from headers and optional JWT.

    Resolution strategy:
    - Tenant id: prefer explicit X-Tenant-ID header (configurable). If missing, try 'tenant_id' claim from JWT.
    - JWT: when Authorization: Bearer <token> is present, decode with configured secret/algorithm (MVP).
      Extract subject/email/roles/tenant_id when available.

    Raises:
        HTTPException 401/400 if tenant cannot be determined.
    """
    settings = get_settings()

    # Normalize header name for tenant
    tenant_header = settings.TENANT_HEADER_NAME
    # FastAPI auto-lowercases header keys in request.headers; use that mapping
    req_tenant = request.headers.get(tenant_header.lower())
    tenant_id = x_tenant_id or req_tenant or settings.DEFAULT_TENANT_ID

    roles: list[str] = []
    user_id: Optional[str] = None
    email: Optional[str] = None
    jwt_sub: Optional[str] = None

    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()

    if token:
        try:
            claims = jwt.decode(
                token,
                settings.JWT_STATE_SECRET,  # For MVP reuse same secret; replace with dedicated APP_JWT_* later
                algorithms=[settings.JWT_ALGORITHM],
                options={"verify_exp": False},  # Adjust as needed
            )
            # Try tenant from claim if not provided in header
            tenant_id = tenant_id or claims.get("tenant_id")
            user_id = claims.get("user_id") or claims.get("sub") or None
            email = claims.get("email")
            jwt_sub = claims.get("sub")
            claim_roles = claims.get("roles") or claims.get("role") or []
            if isinstance(claim_roles, str):
                roles = [claim_roles]
            elif isinstance(claim_roles, list):
                roles = [str(r) for r in claim_roles]
        except Exception:
            # For MVP, if JWT invalid, proceed without JWT-derived fields (but still require tenant)
            pass

    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing tenant identifier.")

    return TenantContext(tenant_id=tenant_id, user_id=user_id, email=email, roles=roles, jwt_sub=jwt_sub)


# PUBLIC_INTERFACE
async def enforce_tenant_match(ctx: TenantContext, claimed_tenant_id: str) -> None:
    """
    Enforce the route-provided tenant_id matches the authenticated/request tenant context.

    Raises:
        HTTPException 403 if mismatch.
    """
    if not ctx.can_access_tenant(claimed_tenant_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant access denied.")


# PUBLIC_INTERFACE
async def authorize_connection_access(ctx: TenantContext, connection_id: str) -> None:
    """
    Placeholder for connection-level authorization.
    For MVP: ensure that operations always specify the tenant_id and that the token store query
    uses both tenant_id and connection_id, providing isolation.

    This hook is where you'd verify that the user has access to the given connection (RBAC lookup).
    """
    # In MVP we don't check DB for membership; tenant match + presence is considered authorized.
    if not connection_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing connection_id.")


# ----- Audit Logging -----

class AuditEvent(BaseModel):
    """Represents a single audit log entry."""
    tenant_id: str = Field(..., description="Tenant id at time of event.")
    actor_user_id: Optional[str] = Field(default=None, description="Actor user id if available.")
    actor_email: Optional[str] = Field(default=None, description="Actor email if available.")
    action: str = Field(..., description="Action name, e.g., 'auth.set_api_key', 'connector.search'.")
    target: Dict[str, Any] = Field(default_factory=dict, description="Target entity info, e.g., provider/connection/kind.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional context details.")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Event timestamp (UTC).")


def _audit_collection(tenant_id: str):
    # Single shared collection; always filter by tenant_id on queries.
    return get_tenant_collection("audit_events", tenant_id)


# PUBLIC_INTERFACE
async def write_audit_event(ctx: TenantContext, event: AuditEvent) -> None:
    """
    Write an audit event to the database. Best-effort; swallows errors.

    Parameters:
        ctx: TenantContext
        event: AuditEvent to persist
    """
    try:
        coll = _audit_collection(ctx.tenant_id)
        await coll.insert_one({
            **event.model_dump(),
            "tenant_id": ctx.tenant_id,  # Ensure tenant is set from context
        })
    except Exception:
        # Do not block user requests on audit failures
        pass
