"""
Common async MongoDB data layer using Motor and Pydantic models.

This module provides:
- Async database initialization and accessors
- A small repository helper with common CRUD helpers
- BaseModel config used by all models
- Crypto utility hooks (placeholders) to encrypt/decrypt fields at rest

Environment variables required (should be set in .env by the orchestrator):
- MONGODB_URI: MongoDB connection string (e.g., mongodb+srv://...)
- MONGODB_DB: Database name for this backend (e.g., connector_platform)
- ENCRYPTION_KEY: Base64-encoded 32-byte key used to encrypt sensitive token fields

Notes:
- We do not hardcode secrets; they must be provided via env.
- Encryption helper functions are implemented with Fernet if key is provided.
"""
from __future__ import annotations

import base64
import os
from datetime import datetime
from typing import Any, Dict, Generic, List, Optional, Protocol, Tuple, Type, TypeVar

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection, AsyncIOMotorDatabase
from pydantic import BaseModel, Field, ConfigDict, ValidationError

try:
    from cryptography.fernet import Fernet, InvalidToken
except Exception:  # pragma: no cover - cryptography may not be installed in CI image
    Fernet = None  # type: ignore
    InvalidToken = Exception  # type: ignore

_DB_CLIENT: Optional[AsyncIOMotorClient] = None
_DB: Optional[AsyncIOMotorDatabase] = None
_ENCRYPTER: Optional["Encrypter"] = None


class Encrypter(Protocol):
    def encrypt(self, plaintext: str) -> str: ...
    def decrypt(self, ciphertext: str) -> str: ...


class FernetEncrypter:
    """Wraps Fernet symmetric encryption with urlsafe base64 text outputs."""

    def __init__(self, key_b64: str):
        key = key_b64.encode("utf-8")
        # Validate key length by decoding
        try:
            _ = base64.urlsafe_b64decode(key)
        except Exception as e:
            raise ValueError("ENCRYPTION_KEY must be base64-url-safe encoded bytes") from e
        if Fernet is None:
            raise RuntimeError("cryptography package not available for encryption")
        self._fernet = Fernet(key)

    def encrypt(self, plaintext: str) -> str:
        token = self._fernet.encrypt(plaintext.encode("utf-8"))
        return token.decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        try:
            data = self._fernet.decrypt(ciphertext.encode("utf-8"))
            return data.decode("utf-8")
        except InvalidToken as e:
            raise ValueError("Failed to decrypt token with provided key") from e


def get_database() -> AsyncIOMotorDatabase:
    """
    PUBLIC_INTERFACE
    Returns the shared AsyncIOMotorDatabase instance.

    Raises:
        RuntimeError if database was not initialized.
    """
    if _DB is None:
        raise RuntimeError("Database not initialized. Call init_database() on startup.")
    return _DB


async def init_database() -> None:
    """
    PUBLIC_INTERFACE
    Initialize the shared MongoDB client and database.

    Reads MONGODB_URI and MONGODB_DB from the environment.
    Optionally sets up encryption if ENCRYPTION_KEY is present.
    """
    global _DB_CLIENT, _DB, _ENCRYPTER
    if _DB is not None:
        return

    mongo_uri = os.getenv("MONGODB_URI")
    mongo_db = os.getenv("MONGODB_DB")
    if not mongo_uri or not mongo_db:
        raise RuntimeError("MONGODB_URI and MONGODB_DB must be set in the environment")

    _DB_CLIENT = AsyncIOMotorClient(mongo_uri)
    _DB = _DB_CLIENT[mongo_db]

    enc_key = os.getenv("ENCRYPTION_KEY")
    if enc_key:
        _ENCRYPTER = FernetEncrypter(enc_key)
    else:
        _ENCRYPTER = None


def get_collection(name: str) -> AsyncIOMotorCollection:
    """
    PUBLIC_INTERFACE
    Get a collection from the initialized database by name.
    """
    return get_database()[name]


def get_encrypter() -> Optional[Encrypter]:
    """
    PUBLIC_INTERFACE
    Get the configured Encrypter if encryption is enabled, otherwise None.
    """
    return _ENCRYPTER


TModel = TypeVar("TModel", bound=BaseModel)


class Repo(Generic[TModel]):
    """A tiny async repository layer built on Motor and Pydantic models."""

    def __init__(self, collection: AsyncIOMotorCollection, model: Type[TModel]):
        self.collection = collection
        self.model = model

    async def get_by_id(self, _id: Any) -> Optional[TModel]:
        doc = await self.collection.find_one({"_id": _id})
        if not doc:
            return None
        return self.model.model_validate(doc)

    async def find_one(self, query: Dict[str, Any]) -> Optional[TModel]:
        doc = await self.collection.find_one(query)
        if not doc:
            return None
        return self.model.model_validate(doc)

    async def find(self, query: Dict[str, Any], limit: int = 50) -> List[TModel]:
        cursor = self.collection.find(query).limit(limit)
        items: List[TModel] = []
        async for doc in cursor:
            items.append(self.model.model_validate(doc))
        return items

    async def upsert(self, query: Dict[str, Any], data: Dict[str, Any]) -> Tuple[bool, TModel]:
        """Upsert and return the saved document. Returns (created, model)."""
        result = await self.collection.find_one_and_update(
            query, {"$set": data}, upsert=True, return_document=True
        )
        # When upsert creates, Mongo may not return doc; fetch to be safe
        if not result:
            result = await self.collection.find_one(query)
        created = False
        if result and "_id" not in result:
            created = True
        return created, self.model.model_validate(result)

    async def insert_one(self, data: Dict[str, Any]) -> TModel:
        await self.collection.insert_one(data)
        return self.model.model_validate(data)

    async def update_one(self, query: Dict[str, Any], update: Dict[str, Any]) -> int:
        res = await self.collection.update_one(query, {"$set": update})
        return res.modified_count

    async def delete_one(self, query: Dict[str, Any]) -> int:
        res = await self.collection.delete_one(query)
        return res.deleted_count


class MongoBaseModel(BaseModel):
    """Common BaseModel config with Mongo-friendly options."""

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        str_strip_whitespace=True,
        extra="ignore",
        protected_namespaces=(),
        json_encoders={datetime: lambda dt: dt.isoformat()},
        ser_json_inf_nan=True,
    )
