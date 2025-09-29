from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.core.config import get_settings
from src.core.db import lifespan_shutdown, lifespan_startup
from src.routers.connectors import router as connectors_router
from src.routers.auth import router as auth_router

settings = get_settings()


@asynccontextmanager
async def app_lifespan(_app: FastAPI):
    # Startup
    await lifespan_startup()
    try:
        yield
    finally:
        # Shutdown
        await lifespan_shutdown()


openapi_tags = [
    {"name": "health", "description": "Service health and diagnostics."},
    {"name": "connectors", "description": "Connector discovery and operations."},
    {"name": "auth", "description": "Credential management (API Key/OAuth)."},
    {"name": "oauth", "description": "OAuth authorization and token lifecycle."},
]

app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
    openapi_tags=openapi_tags,
    lifespan=app_lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOW_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=settings.CORS_ALLOW_METHODS,
    allow_headers=list(set(settings.CORS_ALLOW_HEADERS + [get_settings().TENANT_HEADER_NAME])),
)

# Register routers
app.include_router(connectors_router)
app.include_router(auth_router)


@app.get(
    "/",
    tags=["health"],
    summary="Health Check",
    description="Returns service health and basic info.",
    response_description="A JSON object indicating service health.",
)
def health_check():
    """
    Health endpoint for uptime checks.

    Returns:
        JSON with a simple message and environment metadata.
    """
    return {"message": "Healthy", "env": settings.ENVIRONMENT, "version": settings.APP_VERSION}
