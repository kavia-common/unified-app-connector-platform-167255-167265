"""
Models package entrypoint.

Provides a single init_models() to be called on app startup that:
- Initializes database connection
- Ensures all collection indexes exist
"""
from __future__ import annotations

from .base import init_database
from .tenant import init_tenant_indexes
from .user_token import init_user_token_indexes
from .connector import init_connector_indexes
from .rate_limit import init_rate_limit_indexes


async def init_models() -> None:
    """
    PUBLIC_INTERFACE
    Initialize database and ensure indexes for all models.
    """
    await init_database()
    await init_tenant_indexes()
    await init_user_token_indexes()
    await init_connector_indexes()
    await init_rate_limit_indexes()
