"""
Connector registry model and repository.

Represents available connectors for a tenant and their configuration/state.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import Field

from .base import MongoBaseModel, Repo, get_collection


CONNECTORS_COLL = "connectors"


class Connector(MongoBaseModel):
    """
    PUBLIC_INTERFACE
    Connector registration state.

    Uniqueness per tenant: (tenant_id, key) must be unique.
    """
    _id: Optional[str] = Field(default=None, description="Mongo generated ID")
    tenant_id: str = Field(..., description="Tenant id")
    key: str = Field(..., description="Connector key (e.g., 'jira', 'confluence')")
    provider: str = Field(..., description="Provider label (e.g., 'atlassian')")
    display_name: str = Field(..., description="Display name for UI")
    enabled: bool = Field(default=True, description="Whether connector is enabled")

    client_id: Optional[str] = Field(default=None, description="OAuth client id (if applicable)")
    client_secret: Optional[str] = Field(default=None, description="OAuth client secret (store in secret store ideally)")
    auth_type: str = Field(default="oauth", description="oauth | api_key | none")

    # Operation flags for capabilities in UI and agents
    operations: Dict[str, bool] = Field(
        default_factory=lambda: {
            "search": True,
            "create": False,
            "update": False,
            "delete": False,
            "list_projects": True,
        },
        description="Capability flags",
    )

    settings: Dict[str, Any] = Field(default_factory=dict, description="Provider specific settings")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Created at UTC")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Updated at UTC")


class ConnectorRepo(Repo[Connector]):
    """Repository for connector registry with helper queries."""

    def __init__(self) -> None:
        super().__init__(get_collection(CONNECTORS_COLL), Connector)

    async def ensure_indexes(self) -> None:
        await self.collection.create_index(
            [("tenant_id", 1), ("key", 1)],
            unique=True,
            name="uniq_tenant_connector_key",
        )
        await self.collection.create_index("enabled")
        await self.collection.create_index("provider")

    async def upsert_connector(self, tenant_id: str, key: str, data: Dict[str, Any]) -> Connector:
        payload = {
            **data,
            "tenant_id": tenant_id,
            "key": key,
            "updated_at": datetime.utcnow(),
        }
        await self.collection.update_one(
            {"tenant_id": tenant_id, "key": key},
            {"$set": Connector.model_validate(payload).model_dump()},
            upsert=True,
        )
        doc = await self.collection.find_one({"tenant_id": tenant_id, "key": key})
        return Connector.model_validate(doc)


async def init_connector_indexes() -> None:
    """
    PUBLIC_INTERFACE
    Ensure connector collection indexes are created.
    """
    await ConnectorRepo().ensure_indexes()
