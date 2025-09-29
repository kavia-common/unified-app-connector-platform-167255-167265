from __future__ import annotations

from fastapi import Request
from slowapi.util import get_remote_address


# PUBLIC_INTERFACE
def key_by_tenant(request: Request) -> str:
    """Return a per-tenant rate limit key when available; fallback to client IP.
    This function avoids leaking any sensitive values. It only uses the x-tenant-id header value as-is.
    """
    tenant_id = request.headers.get("x-tenant-id")
    if tenant_id:
        return f"tenant:{tenant_id}"
    return get_remote_address(request)


# PUBLIC_INTERFACE
def key_by_user_or_tenant(request: Request) -> str:
    """Return a per-user (coarse) key when Authorization header exists; else fallback to tenant or IP.
    We do not include actual token content to avoid leakage; presence is enough for scoping.
    """
    if request.headers.get("authorization"):
        tenant = request.headers.get("x-tenant-id") or "unknown"
        return f"user:tenant:{tenant}"
    return key_by_tenant(request)
