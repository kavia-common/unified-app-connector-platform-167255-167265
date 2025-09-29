"""
FastAPI application entry point.

Wires models init and registers API routers and global error handlers.
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .models import init_models
from .api import api_router
from .utils.errors import ApiError, ErrorCode, standard_response

app = FastAPI(
    title="Connector Backend API",
    description="Backend for multi-tenant connectors, token management, and rate limiting",
    version="0.1.0",
    openapi_tags=[
        {"name": "tenants", "description": "Tenant operations"},
        {"name": "connectors", "description": "Connector registry"},
        {"name": "auth", "description": "Auth and tokens"},
        {"name": "rate-limit", "description": "Rate limiting and usage"},
        {"name": "operations", "description": "Search/Create operations"},
        {"name": "ai", "description": "LLM proxy and AI tools"},
    ],
)


@app.on_event("startup")
async def on_startup() -> None:
    """
    PUBLIC_INTERFACE
    FastAPI startup hook to initialize database and indexes.
    """
    await init_models()


@app.get("/healthz", tags=["tenants"], summary="Health check", description="Simple health probe")
async def healthz() -> dict:
    """
    PUBLIC_INTERFACE
    Basic health check endpoint.
    """
    return {"status": "ok"}


# Register routers
app.include_router(api_router)


# Global error handler for ApiError -> JSON envelope
@app.exception_handler(ApiError)
async def api_error_handler(request: Request, exc: ApiError):
    return JSONResponse(
        status_code=400,
        content={"status": "error", "error": {"code": exc.code, "message": exc.message, "details": exc.details}},
    )
