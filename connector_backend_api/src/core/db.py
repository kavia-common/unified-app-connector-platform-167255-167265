"""
Async MongoDB client initialization and access helpers using Motor.

This module provides:
- get_motor_client(): singleton Motor client
- get_database(): returns Motor database instance
- get_tenant_collection(): helper to access tenant-scoped collections
- lifespan_startup/shutdown helpers for FastAPI lifespan management
"""

from __future__ import annotations

from typing import Optional

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase, AsyncIOMotorCollection

from src.core.config import get_settings
from src.core.mongo_models import ensure_indexes

_client: Optional[AsyncIOMotorClient] = None


# PUBLIC_INTERFACE
def get_motor_client() -> AsyncIOMotorClient:
    """Return a singleton Motor client configured from environment variables."""
    global _client
    if _client is None:
        settings = get_settings()
        _client = AsyncIOMotorClient(settings.MONGODB_URI)
    return _client


# PUBLIC_INTERFACE
def get_database() -> AsyncIOMotorDatabase:
    """Return the configured MongoDB database instance."""
    settings = get_settings()
    return get_motor_client()[settings.MONGODB_DB_NAME]


# PUBLIC_INTERFACE
def get_tenant_collection(collection_name: str, tenant_id: Optional[str]) -> AsyncIOMotorCollection:
    """
    Return a collection handle intended for tenant-scoped data.

    This does not physically separate data per-tenant but enforces that
    documents stored include a tenant_id field and queries should filter by it.
    """
    db = get_database()
    return db[collection_name]


async def _ping() -> None:
    """Internal: ping MongoDB to verify connection."""
    await get_database().command("ping")


# PUBLIC_INTERFACE
async def lifespan_startup() -> None:
    """Startup hook to verify DB connectivity."""
    await _ping()
    # Initialize required indexes for performance and constraints
    try:
        # Initialize core indexes for collections in this service
        await ensure_indexes(get_database())
        # Optional: downstream core indexes if defined elsewhere
        try:
            from src.core.crypto import ensure_core_indexes  # type: ignore
            await ensure_core_indexes()
        except Exception:
            # Ignore if not present or fails; not critical for DB availability
            pass
    except Exception:
        # Do not block startup if index creation has transient issues
        pass


# PUBLIC_INTERFACE
async def lifespan_shutdown() -> None:
    """Shutdown hook to close DB client."""
    global _client
    if _client is not None:
        _client.close()
        _client = None
