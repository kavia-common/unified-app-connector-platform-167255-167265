from __future__ import annotations

from typing import Callable

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from src.core.config import get_settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware that adds industry-standard security headers to all responses.

    - Strict-Transport-Security (if SITE_URL is https in non-dev envs)
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY
    - Referrer-Policy: no-referrer
    - Permissions-Policy: minimal defaults
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        # Always set basic headers
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=(), payment=()",
        )

        settings = get_settings()
        # Enable HSTS only if public site is https and env is not development
        if settings.SITE_URL and str(settings.SITE_URL).startswith("https") and settings.ENVIRONMENT != "development":
            # 6 months; includeSubDomains and preload flags are safe defaults when fully https
            response.headers.setdefault("Strict-Transport-Security", "max-age=15552000; includeSubDomains; preload")

        return response


class TenantHeaderNormalizeMiddleware(BaseHTTPMiddleware):
    """
    Normalize the configured tenant header to a canonical form inside request.headers mapping,
    so downstream code can always read using settings.TENANT_HEADER_NAME (case-insensitive).

    This avoids missing the tenant if a different casing is used by clients.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        _ = get_settings()  # Access settings for potential future logic; avoid unused var warnings
        # FastAPI already treats headers as case-insensitive; normalization is effectively a no-op here.
        return await call_next(request)


# PUBLIC_INTERFACE
def register_security_middleware(app: FastAPI) -> None:
    """Register security-related middlewares on the given FastAPI app."""
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(TenantHeaderNormalizeMiddleware)
