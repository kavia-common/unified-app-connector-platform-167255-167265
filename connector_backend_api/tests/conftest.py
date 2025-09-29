# pytest fixtures and helpers for FastAPI app testing

import os
import typing as t
import pytest
from fastapi.testclient import TestClient

# Ensure app uses predictable env
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("APP_NAME", "Connector Backend API")
os.environ.setdefault("APP_DESCRIPTION", "Test Instance")
os.environ.setdefault("APP_VERSION", "0.1.0")
os.environ.setdefault("SITE_URL", "http://localhost:3000")
os.environ.setdefault("TENANT_HEADER_NAME", "x-tenant-id")
# cryptography/testing: provide a static key for EncryptionManager
os.environ.setdefault("ENCRYPTION_KEY", "a" * 32)  # 32 chars ~ 256-bit key
os.environ.setdefault("ENCRYPTION_KEY_VERSION", "v1")

from src.api.main import app  # noqa: E402
from src.core.tenant import TenantContext  # noqa: E402


@pytest.fixture(scope="session")
def test_tenant() -> str:
    return "tenant-test"


@pytest.fixture(scope="session")
def test_connection() -> str:
    return "conn-1"


@pytest.fixture(autouse=True)
def patch_tenant_context(monkeypatch, test_tenant):
    """
    Patch get_tenant_context to avoid JWT/headers complexity.
    Provide a static TenantContext for tests.
    """
    from src.core import tenant as tenant_mod

    async def fake_get_ctx():
        return TenantContext(
            tenant_id=test_tenant,
            user_id="user-1",
            email="test@example.com",
            roles=["admin"],
            raw_token=None,
        )

    monkeypatch.setattr(tenant_mod, "get_tenant_context", fake_get_ctx)
    return


@pytest.fixture(autouse=True)
def patch_db(monkeypatch, test_tenant):
    """
    Patch DB utilities to avoid real MongoDB.
    We emulate collections with simple in-memory dicts keyed by (tenant_id, collection_name).
    """
    from src.core import db as db_mod

    store: dict[tuple[str, str], list[dict]] = {}

    class FakeCollection:
        def __init__(self, key: tuple[str, str]):
            self._key = key

        async def update_one(self, query: dict, update: dict, upsert: bool = False):
            # Simple upsert into the list using a composite key match
            items = store.setdefault(self._key, [])
            # find item
            idx = None
            for i, doc in enumerate(items):
                match = all(doc.get(k) == v for k, v in query.items())
                if match:
                    idx = i
                    break
            set_doc = update.get("$set", {})
            set_on_insert = update.get("$setOnInsert", {})
            if idx is not None:
                items[idx].update(set_doc)
                return
            if upsert:
                new_doc = {}
                new_doc.update(query)
                new_doc.update(set_doc)
                new_doc.update({k: v for k, v in set_on_insert.items() if k not in new_doc})
                items.append(new_doc)

        async def find_one(self, query: dict):
            items = store.get(self._key, [])
            for doc in items:
                if all(doc.get(k) == v for k, v in query.items()):
                    return doc
            return None

    def get_tenant_collection(name: str, tenant_id: str):
        key = (tenant_id, name)
        return FakeCollection(key)

    async def lifespan_startup():
        return None

    async def lifespan_shutdown():
        return None

    monkeypatch.setattr(db_mod, "get_tenant_collection", get_tenant_collection)
    monkeypatch.setattr(db_mod, "lifespan_startup", lifespan_startup)
    monkeypatch.setattr(db_mod, "lifespan_shutdown", lifespan_shutdown)
    return store


@pytest.fixture(autouse=True)
def patch_security(monkeypatch):
    """
    Make oauth state encoding/decoding deterministic.
    """
    from src.core import security as sec

    def encode_oauth_state(payload: dict) -> str:
        # Simple stub: join keys for predictability
        return f"state|{payload.get('tenant_id')}|{payload.get('connection_id')}|{payload.get('connector')}|fixed"

    def decode_oauth_state(state: str) -> dict:
        parts = state.split("|")
        if len(parts) < 5 or parts[0] != "state":
            raise ValueError("bad-state")
        return {
            "tenant_id": parts[1],
            "connection_id": parts[2],
            "connector": parts[3],
            "nonce": parts[4],
        }

    monkeypatch.setattr(sec, "encode_oauth_state", encode_oauth_state)
    monkeypatch.setattr(sec, "decode_oauth_state", decode_oauth_state)


@pytest.fixture(autouse=True)
def patch_encryption_manager(monkeypatch):
    """
    Provide no-op deterministic EncryptionManager for tests.
    """
    from src.core import crypto as crypto_mod

    class FakeEnc:
        key_version = "vtest"

        @classmethod
        def from_env(cls):
            return cls()

        def encrypt(self, plaintext: t.Optional[str], aad: bytes | None = None) -> dict | None:
            if plaintext is None:
                return None
            # store as simple dict to simulate ciphertext structure
            return {"ct": plaintext, "aad": (aad.decode() if aad else None), "v": self.key_version}

        def decrypt(self, ciphertext: dict, aad: bytes | None = None) -> str:
            # ignore aad check for simplicity
            return ciphertext.get("ct")

    monkeypatch.setattr(crypto_mod, "EncryptionManager", FakeEnc)


@pytest.fixture(autouse=True)
def patch_rate_limit(monkeypatch):
    """
    Disable rate limit checks in tests.
    """
    from src.core import errors as err

    def noop_rate_limit_check(*args, **kwargs):
        return None

    monkeypatch.setattr(err, "rate_limit_check", noop_rate_limit_check)


@pytest.fixture
def client() -> TestClient:
    """
    FastAPI TestClient for sync tests. Under the hood, it will run async endpoints.
    """
    return TestClient(app)
