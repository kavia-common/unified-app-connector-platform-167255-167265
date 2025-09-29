"""
Tenant model and repository for multi-tenant support.

A Tenant is the logical organization boundary. Users and connectors are associated
to a tenant via tenant_id.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import Field

from .base import MongoBaseModel, Repo, get_collection, get_database


TENANTS_COLL = "tenants"


class Tenant(MongoBaseModel):
    """
    PUBLIC_INTERFACE
    Represents a tenant (organization/workspace).

    Fields:
      - _id: Unique id (slug or uuid)
      - name: Human readable name
      - created_at: Creation timestamp
      - updated_at: Last updated timestamp
      - metadata: Optional dict for extra info (e.g., billing tier)
    """
    _id: str = Field(..., description="Tenant unique identifier (slug or uuid)")
    name: str = Field(..., description="Tenant display name")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Created at UTC")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Updated at UTC")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Arbitrary metadata")


class TenantRepo(Repo[Tenant]):
    """Repository for tenants with common helpers."""

    def __init__(self) -> None:
        super().__init__(get_collection(TENANTS_COLL), Tenant)

    async def ensure_indexes(self) -> None:
        # Unique index on _id (default), and name non-unique for search
        await self.collection.create_index("_id", unique=True)
        await self.collection.create_index("name")


async def init_tenant_indexes() -> None:
    """
    PUBLIC_INTERFACE
    Ensure tenant collection indexes are created.
    """
    await TenantRepo().ensure_indexes()
