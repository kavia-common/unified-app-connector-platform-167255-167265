"""
UserToken model for storing OAuth/API keys per user per tenant per connector.

Sensitive fields are encrypted if ENCRYPTION_KEY is configured.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import Field, model_validator

from .base import MongoBaseModel, Repo, get_collection, get_encrypter


USER_TOKENS_COLL = "user_tokens"


class UserToken(MongoBaseModel):
    """
    PUBLIC_INTERFACE
    Stores credentials per user per tenant per connector.

    Uniqueness: (tenant_id, user_id, connector_key) must be unique.
    """
    _id: Optional[str] = Field(default=None, description="Mongo generated ID")
    tenant_id: str = Field(..., description="Tenant identifier")
    user_id: str = Field(..., description="User identifier within tenant")
    connector_key: str = Field(..., description="Connector key (e.g., 'jira', 'confluence')")

    # Sensitive fields (encrypted if encrypter available)
    access_token: Optional[str] = Field(default=None, description="Access token (encrypted at rest)")
    refresh_token: Optional[str] = Field(default=None, description="Refresh token (encrypted at rest)")
    api_key: Optional[str] = Field(default=None, description="API key (encrypted at rest)")

    expires_at: Optional[datetime] = Field(default=None, description="Token expiry (UTC)")
    scopes: Optional[list[str]] = Field(default=None, description="Granted scopes")

    created_at: datetime = Field(default_factory=datetime.utcnow, description="Created at UTC")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Updated at UTC")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Provider specific data")

    @model_validator(mode="before")
    @classmethod
    def encrypt_sensitive(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt sensitive values on input if possible."""
        enc = get_encrypter()
        if enc:
            for key in ("access_token", "refresh_token", "api_key"):
                if values.get(key) and not str(values[key]).startswith("gAAAAA"):  # Fernet marker heuristic
                    values[key] = enc.encrypt(str(values[key]))
        return values

    def decrypted(self) -> "UserToken":
        """
        PUBLIC_INTERFACE
        Return a copy with decrypted sensitive fields if encrypter is configured.
        """
        enc = get_encrypter()
        if not enc:
            return self

        def _dec(v: Optional[str]) -> Optional[str]:
            if not v:
                return v
            try:
                return enc.decrypt(v)
            except Exception:
                return v

        return self.model_copy(
            update={
                "access_token": _dec(self.access_token),
                "refresh_token": _dec(self.refresh_token),
                "api_key": _dec(self.api_key),
            }
        )


class UserTokenRepo(Repo[UserToken]):
    """Repository for user tokens with helper upserts."""

    def __init__(self) -> None:
        super().__init__(get_collection(USER_TOKENS_COLL), UserToken)

    async def ensure_indexes(self) -> None:
        # Unique compound to avoid duplicates
        await self.collection.create_index(
            [("tenant_id", 1), ("user_id", 1), ("connector_key", 1)],
            unique=True,
            name="uniq_tenant_user_connector",
        )
        await self.collection.create_index("expires_at")

    async def upsert_token(
        self,
        tenant_id: str,
        user_id: str,
        connector_key: str,
        data: Dict[str, Any],
    ) -> UserToken:
        data = {
            **data,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "connector_key": connector_key,
            "updated_at": datetime.utcnow(),
        }
        await self.collection.update_one(
            {"tenant_id": tenant_id, "user_id": user_id, "connector_key": connector_key},
            {"$set": UserToken.model_validate(data).model_dump()},
            upsert=True,
        )
        doc = await self.collection.find_one(
            {"tenant_id": tenant_id, "user_id": user_id, "connector_key": connector_key}
        )
        return UserToken.model_validate(doc)


async def init_user_token_indexes() -> None:
    """
    PUBLIC_INTERFACE
    Ensure user token collection indexes are created.
    """
    await UserTokenRepo().ensure_indexes()
