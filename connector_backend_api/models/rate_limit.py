"""
Rate limiting storage for tracking usage by tenant/connector/user.

Provides atomic counters with TTL windows to enforce limits externally
(e.g., middleware or endpoint handlers can consult and update).
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from pydantic import Field

from .base import MongoBaseModel, Repo, get_collection


RATE_LIMIT_COLL = "rate_limits"


class RateLimit(MongoBaseModel):
    """
    PUBLIC_INTERFACE
    Rate limit state document.

    Uniqueness: (tenant_id, connector_key, user_id, window_start, window_sec)
    """
    _id: Optional[str] = Field(default=None, description="Mongo generated ID")
    tenant_id: str = Field(..., description="Tenant id")
    connector_key: str = Field(..., description="Connector key")
    user_id: Optional[str] = Field(default=None, description="Optional user id")
    window_start: datetime = Field(..., description="Window start UTC (bucketed)")
    window_sec: int = Field(..., description="Window length in seconds")
    count: int = Field(default=0, description="Number of hits in window")
    limit: int = Field(default=60, description="Configured limit for this key")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Created at UTC")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Updated at UTC")


class RateLimitRepo(Repo[RateLimit]):
    """Repository with atomic increment helper."""

    def __init__(self) -> None:
        super().__init__(get_collection(RATE_LIMIT_COLL), RateLimit)

    async def ensure_indexes(self) -> None:
        await self.collection.create_index(
            [
                ("tenant_id", 1),
                ("connector_key", 1),
                ("user_id", 1),
                ("window_start", 1),
                ("window_sec", 1),
            ],
            unique=True,
            name="uniq_rl_window",
        )
        await self.collection.create_index("updated_at")

    async def increment_and_get(
        self,
        tenant_id: str,
        connector_key: str,
        window_sec: int,
        user_id: Optional[str] = None,
        increment: int = 1,
        limit: int = 60,
    ) -> RateLimit:
        """
        PUBLIC_INTERFACE
        Atomically increment usage counter for the current window and return the document.
        """
        now = datetime.utcnow()
        # Bucket start
        window_start = now - timedelta(seconds=now.timestamp() % window_sec)
        query = {
            "tenant_id": tenant_id,
            "connector_key": connector_key,
            "user_id": user_id,
            "window_start": window_start,
            "window_sec": window_sec,
        }
        update = {
            "$setOnInsert": {
                "created_at": now,
                "limit": limit,
            },
            "$set": {
                "updated_at": now,
            },
            "$inc": {
                "count": increment,
            },
        }
        await self.collection.update_one(query, update, upsert=True)
        doc = await self.collection.find_one(query)
        return RateLimit.model_validate(doc)


async def init_rate_limit_indexes() -> None:
    """
    PUBLIC_INTERFACE
    Ensure rate limit collection indexes are created.
    """
    await RateLimitRepo().ensure_indexes()
