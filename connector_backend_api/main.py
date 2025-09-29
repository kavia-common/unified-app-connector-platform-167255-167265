"""
FastAPI application entry point (skeleton).

This file wires the models init to startup for ensuring DB and indexes.
"""
from __future__ import annotations

from fastapi import FastAPI

from .models import init_models

app = FastAPI(
    title="Connector Backend API",
    description="Backend for multi-tenant connectors, token management, and rate limiting",
    version="0.1.0",
    openapi_tags=[
        {"name": "tenants", "description": "Tenant operations"},
        {"name": "connectors", "description": "Connector registry"},
        {"name": "auth", "description": "Auth and tokens"},
        {"name": "rate-limit", "description": "Rate limiting and usage"},
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
