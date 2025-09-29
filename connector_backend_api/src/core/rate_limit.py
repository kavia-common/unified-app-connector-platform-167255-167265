from __future__ import annotations

from typing import Optional

from fastapi import Request, Response
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address


# PUBLIC_INTERFACE
def get_rate_limiter() -> Limiter:
    """
    Create and return the global SlowAPI Limiter instance for the app.

    The limiter is configured to use:
    - global key: client's IP address
    - supports custom keys: per-tenant and per-user when available

    Returns:
        Limiter: Configured rate limiter instance.
    """
    # Using in-memory storage by default; can be switched to Redis by configuring Limiter(storage_uri="redis://...")
    return Limiter(key_func=get_remote_address, headers_enabled=True)


# PUBLIC_INTERFACE
def rate_limit_key_tenant(request: Request) -> str:
    """
    Build a rate limit key based on tenant when 'x-tenant-id' header is provided.

    Fallbacks to IP address to avoid blocking multiple tenants behind the same IP.

    Returns:
        str: A per-tenant key if available, otherwise client IP.
    """
    tenant_id = _get_tenant_id(request)
    if tenant_id:
        return f"tenant:{tenant_id}"
    return get_remote_address(request)  # fallback


# PUBLIC_INTERFACE
def rate_limit_key_user(request: Request) -> str:
    """
    Build a rate limit key based on authenticated user (if provided via Authorization).
    If not present, fallback to tenant, then IP.

    This avoids leaking the auth token by not including raw token values.
    It uses a generic 'user' label when Authorization header exists.

    Returns:
        str: best-effort scoped key.
    """
    # Note: Do NOT echo or hash the token to avoid any leakage.
    auth = request.headers.get("authorization")
    if auth:
        tenant = _get_tenant_id(request) or "unknown"
        return f"user:tenant:{tenant}"
    # fallback to tenant, then IP
    return rate_limit_key_tenant(request)


def _get_tenant_id(request: Request) -> Optional[str]:
    """
    Internal: safely extract tenant id from header without raising.
    """
    return request.headers.get("x-tenant-id") or None


# PUBLIC_INTERFACE
def register_rate_limit_handler(app) -> None:
    """
    Registers the SlowAPI rate limit exception handler with a sanitized response shape.

    The returned 429 JSON body is kept generic to avoid leaking endpoint or input details.
    """
    async def sanitized_rl_handler(request: Request, exc: RateLimitExceeded) -> Response:
        # Use default handler to get a base response, then sanitize
        resp: Response = await _rate_limit_exceeded_handler(request, exc)
        # Override body with a sanitized message
        resp.body = b'{"detail":"Too many requests. Please retry later."}'
        resp.media_type = "application/json"
        return resp

    app.add_exception_handler(RateLimitExceeded, sanitized_rl_handler)
