"""
MongoDB collection names, document schemas, and repository helpers.

This module defines:
- Collection names and indexes
- Dataclass-style Pydantic models for persistence (DB-facing)
- CRUD repository helpers that use Motor async collections
- Initialization function to create indexes on startup

We keep API-facing models in src/core/models.py and DB-facing structures here.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field
from pydantic.config import ConfigDict
from motor.motor_asyncio import AsyncIOMotorCollection, AsyncIOMotorDatabase

# Collection names (centralized)
TENANTS_COLL = "tenants"
CONNECTORS_COLL = "connectors"
INTEGRATIONS_COLL = "integrations"  # Connection bindings across services
USERTOKENS_COLL = "user_tokens"  # OAuth/API key credentials by tenant+connection

# ---------- DB-Facing Models ----------

class BaseDBModel(BaseModel):
    """
    Common base for MongoDB-facing models to ensure alias handling and arbitrary types.
    """
    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)


class TenantDoc(BaseDBModel):
    """DB document for Tenant records."""

    id: Optional[str] = Field(default=None, alias="_id", description="Tenant identifier (string ObjectId or custom ID).")
    name: str = Field(..., description="Tenant display name.")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp.")


class ConnectorDoc(BaseDBModel):
    """DB document for a registered connector instance for a tenant."""

    id: Optional[str] = Field(default=None, alias="_id", description="Connection identifier.")
    tenant_id: str = Field(..., description="Owning tenant id.")
    provider: str = Field(..., description="Provider key, e.g., 'jira', 'confluence'.")
    name: str = Field(..., description="Human-friendly name.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary connector metadata (base_url, etc).")
    enabled: bool = Field(default=True, description="Whether this connector is enabled.")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp.")


class IntegrationDoc(BaseDBModel):
    """DB document describing a logical integration configuration."""

    id: Optional[str] = Field(default=None, alias="_id", description="Integration identifier.")
    tenant_id: str = Field(..., description="Tenant id.")
    connection_id: str = Field(..., description="Associated connector/connection id.")
    name: str = Field(..., description="Integration name.")
    settings: Dict[str, Any] = Field(default_factory=dict, description="Integration settings blob.")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp.")


class UserTokenDoc(BaseDBModel):
    """
    DB document for user/connection credentials.

    - For OAuth, tokens are encrypted (AES-GCM envelope as string)
    - For API Key, only salted hash is stored; plaintext never persisted
    """

    id: Optional[str] = Field(default=None, alias="_id", description="Token record id.")
    tenant_id: str = Field(..., description="Tenant id.")
    connection_id: str = Field(..., description="Connection id.")
    kind: str = Field(..., description="Either 'oauth' or 'api_key'.")
    # OAuth fields
    access_token_encrypted: Optional[str] = Field(default=None, description="Encrypted access token.")
    refresh_token_encrypted: Optional[str] = Field(default=None, description="Encrypted refresh token.")
    encryption_key_version: Optional[str] = Field(default=None, description="Key version label.")
    expires_at: Optional[datetime] = Field(default=None, description="Access token expiry (UTC).")
    # API key
    api_key_hash: Optional[str] = Field(default=None, description="Salted hash of API key.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata (header_name, prefix).")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp.")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Last update timestamp.")


# ---------- Index Initialization ----------

async def ensure_indexes(db: AsyncIOMotorDatabase) -> None:
    """
    Create indexes to support common access patterns and enforce uniqueness.

    This is idempotent and safe to call on every startup.
    """
    # Tenants: name unique (optional), commonly lookup by _id
    await db[TENANTS_COLL].create_index([("name", 1)], name="ix_tenants_name", unique=False)

    # Connectors: tenant_id+provider+name for dedup/lookup; connection enable filtering
    await db[CONNECTORS_COLL].create_index(
        [("tenant_id", 1), ("provider", 1)], name="ix_connectors_tenant_provider", unique=False
    )
    await db[CONNECTORS_COLL].create_index([("tenant_id", 1), ("name", 1)], name="ix_connectors_tenant_name", unique=False)
    await db[CONNECTORS_COLL].create_index([("enabled", 1)], name="ix_connectors_enabled", unique=False)

    # Integrations: tenant_id+connection_id common
    await db[INTEGRATIONS_COLL].create_index(
        [("tenant_id", 1), ("connection_id", 1)], name="ix_integrations_tenant_connection", unique=False
    )

    # User Tokens: enforce one token record per tenant+connection
    await db[USERTOKENS_COLL].create_index(
        [("tenant_id", 1), ("connection_id", 1)], name="ux_tokens_tenant_connection", unique=True
    )
    await db[USERTOKENS_COLL].create_index([("expires_at", 1)], name="ix_tokens_expires", unique=False)


# ---------- Repository Helpers ----------

# PUBLIC_INTERFACE
async def upsert_user_token(
    coll: AsyncIOMotorCollection,
    doc: UserTokenDoc,
) -> Tuple[bool, str]:
    """Upsert a user token by (tenant_id, connection_id). Returns (updated, id)."""
    payload = doc.model_dump(exclude_none=True, by_alias=True)
    payload["updated_at"] = datetime.utcnow()

    result = await coll.update_one(
        {"tenant_id": doc.tenant_id, "connection_id": doc.connection_id},
        {"$set": payload, "$setOnInsert": {"created_at": datetime.utcnow()}},
        upsert=True,
    )
    if result.upserted_id is not None:
        return True, str(result.upserted_id)
    # For update, fetch existing id
    existing = await coll.find_one({"tenant_id": doc.tenant_id, "connection_id": doc.connection_id}, {"_id": 1})
    return False, str(existing["_id"]) if existing and "_id" in existing else ""


# PUBLIC_INTERFACE
async def get_user_token(
    coll: AsyncIOMotorCollection, tenant_id: str, connection_id: str
) -> Optional[UserTokenDoc]:
    """Fetch user token record by tenant and connection."""
    data = await coll.find_one({"tenant_id": tenant_id, "connection_id": connection_id})
    return UserTokenDoc(**data) if data else None


# PUBLIC_INTERFACE
async def insert_connector(coll: AsyncIOMotorCollection, doc: ConnectorDoc) -> str:
    """Insert a new connector document and return its id."""
    payload = doc.model_dump(exclude_none=True)
    res = await coll.insert_one(payload)
    return str(res.inserted_id)


# PUBLIC_INTERFACE
async def find_connectors_by_tenant(
    coll: AsyncIOMotorCollection, tenant_id: str, *, provider: Optional[str] = None, enabled: Optional[bool] = None
) -> List[ConnectorDoc]:
    """List connectors for a tenant with optional filters."""
    query: Dict[str, Any] = {"tenant_id": tenant_id}
    if provider is not None:
        query["provider"] = provider
    if enabled is not None:
        query["enabled"] = enabled
    cursor = coll.find(query).sort("created_at", -1)
    return [ConnectorDoc(**doc) async for doc in cursor]


# PUBLIC_INTERFACE
async def insert_integration(coll: AsyncIOMotorCollection, doc: IntegrationDoc) -> str:
    """Insert a new integration and return id."""
    payload = doc.model_dump(exclude_none=True)
    res = await coll.insert_one(payload)
    return str(res.inserted_id)


# PUBLIC_INTERFACE
async def list_integrations(
    coll: AsyncIOMotorCollection, tenant_id: str, connection_id: Optional[str] = None
) -> List[IntegrationDoc]:
    """List integrations for a tenant optionally filtered by connection."""
    query: Dict[str, Any] = {"tenant_id": tenant_id}
    if connection_id:
        query["connection_id"] = connection_id
    cursor = coll.find(query).sort("created_at", -1)
    return [IntegrationDoc(**doc) async for doc in cursor]


# PUBLIC_INTERFACE
def get_collections(db: AsyncIOMotorDatabase) -> Dict[str, AsyncIOMotorCollection]:
    """Return typed collection handles for all core entities."""
    return {
        "tenants": db[TENANTS_COLL],
        "connectors": db[CONNECTORS_COLL],
        "integrations": db[INTEGRATIONS_COLL],
        "user_tokens": db[USERTOKENS_COLL],
    }
