from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.core.config import get_settings
from src.core.db import lifespan_shutdown, lifespan_startup

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
    allow_headers=settings.CORS_ALLOW_HEADERS,
)


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
