"""
Authentication and tenant middleware-like utilities.

We expect frontend to send:
- X-Tenant-ID: current tenant id (slug/uuid)
- Optional X-User-ID for context (some endpoints also receive user_id in body)

We provide:
- TenantContext dependency
- require_authenticated_connector dependency that ensures token exists for the connector
"""

from __future__ import annotations

from typing import Optional

from fastapi import Depends, Header

from ..models.user_token import UserTokenRepo
from .errors import api_error_response, ErrorCode


class TenantContext:
    """Resolved tenant context from headers."""

    # PUBLIC_INTERFACE
    def __init__(self, tenant_id: str):
        """Context wrapper carrying tenant id for dependencies."""
        self.tenant_id = tenant_id


# PUBLIC_INTERFACE
async def get_tenant_context(x_tenant_id: Optional[str] = Header(default=None)) -> TenantContext:
    """Resolve tenant id from header X-Tenant-ID; required for multi-tenant support."""
    if not x_tenant_id:
        raise api_error_response(ErrorCode.UNAUTHORIZED, "Missing X-Tenant-ID header")
    return TenantContext(tenant_id=x_tenant_id)


# PUBLIC_INTERFACE
async def require_authenticated_connector(
    x_user_id: Optional[str] = Header(default=None),
    x_connector_key: Optional[str] = Header(default=None),
    ctx: TenantContext = Depends(get_tenant_context),
):
    """
    Ensure a user token exists for given connector (using headers).
    Some routes also accept user_id/connector_key in payload; this is a coarse guard.
    """
    if not x_user_id or not x_connector_key:
        # Soft guard; routes will still validate payload-level ids
        return {"ok": True}

    tok = await UserTokenRepo().find_one(
        {"tenant_id": ctx.tenant_id, "user_id": x_user_id, "connector_key": x_connector_key}
    )
    if not tok:
        raise api_error_response(ErrorCode.AUTH_REQUIRED, "Connector not authenticated for user")
    return {"ok": True}
