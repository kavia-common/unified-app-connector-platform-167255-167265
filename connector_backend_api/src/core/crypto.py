"""
AES-GCM encryption utilities with key versioning for secure credential storage.

This module provides:
- EncryptionManager: handles AES-GCM encrypt/decrypt using a base64-encoded key from env
- Key versioning: each ciphertext stores a 'k' (key version), 'n' (nonce), 'c' (ciphertext+tag) JSON envelope
- Helpers to initialize MongoDB indexes for token/audit collections

Environment:
- ENCRYPTION_KEY: base64-encoded 32-byte key (AES-256)
- ENCRYPTION_KEY_VERSION: current key version label, e.g., "v1"

Notes:
- If ENCRYPTION_KEY is missing/invalid, encryption operations will raise ValueError.
- To rotate keys, deploy with a new ENCRYPTION_KEY and bump ENCRYPTION_KEY_VERSION; decryption
  should ideally maintain an old key ring. For MVP, we support a single active key and store 'k'
  so future rotation logic can look up legacy keys.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.core.config import get_settings
from src.core.db import get_database


@dataclass
class EncryptionManager:
    """
    PUBLIC_INTERFACE
    Encryption manager using AES-GCM with a single active key from settings.

    Stores ciphertext as JSON string: {"k": "<key_version>", "n": "<nonce_b64>", "c": "<ciphertext_b64>"}
    where ciphertext_b64 includes the GCM tag (AESGCM handles tag internally).
    """
    key_bytes: bytes
    key_version: str

    @staticmethod
    def from_env() -> "EncryptionManager":
        """
        PUBLIC_INTERFACE
        Construct EncryptionManager from environment settings.
        """
        settings = get_settings()
        key_b64 = settings.ENCRYPTION_KEY.strip()
        if not key_b64:
            raise ValueError("ENCRYPTION_KEY is not configured.")
        try:
            key = base64.b64decode(key_b64)
        except Exception as ex:
            raise ValueError(f"ENCRYPTION_KEY is not valid base64: {ex}")
        if len(key) not in (16, 24, 32):
            # Recommend 32 for AES-256; accept 16/24 too to avoid hard failures in dev.
            raise ValueError("ENCRYPTION_KEY length must be 16/24/32 bytes after base64-decoding.")
        version = settings.ENCRYPTION_KEY_VERSION or "v1"
        return EncryptionManager(key_bytes=key, key_version=version)

    # PUBLIC_INTERFACE
    def encrypt(self, plaintext: str, aad: Optional[bytes] = None) -> str:
        """
        Encrypt plaintext into an envelope JSON string.

        Parameters:
            plaintext: utf-8 string to encrypt
            aad: optional additional authenticated data (bytes)

        Returns:
            JSON string containing fields k (version), n (nonce_b64), c (ciphertext_b64_with_tag)
        """
        aesgcm = AESGCM(self.key_bytes)
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
        env = {
            "k": self.key_version,
            "n": base64.b64encode(nonce).decode("utf-8"),
            "c": base64.b64encode(ct).decode("utf-8"),
        }
        return json.dumps(env, separators=(",", ":"))

    # PUBLIC_INTERFACE
    def decrypt(self, envelope: str, aad: Optional[bytes] = None) -> str:
        """
        Decrypt an envelope JSON string created by encrypt().

        Parameters:
            envelope: JSON with fields k, n, c
            aad: optional additional authenticated data (bytes)

        Returns:
            Decrypted utf-8 plaintext.

        Note:
            For MVP we only use the active key; when rotating keys, you can extend this
            to look up legacy keys based on stored 'k'.
        """
        data = json.loads(envelope)
        nonce = base64.b64decode(data["n"])
        ct = base64.b64decode(data["c"])
        aesgcm = AESGCM(self.key_bytes)
        pt = aesgcm.decrypt(nonce, ct, aad)
        return pt.decode("utf-8")


# PUBLIC_INTERFACE
async def ensure_core_indexes() -> None:
    """
    Create MongoDB indexes to optimize tenant/provider/connection lookups.

    Collections and indexes:
    - token_records:
        - unique compound index on {tenant_id, connection_id, kind}
        - non-unique on {tenant_id, kind}
    - audit_events:
        - index on {tenant_id, created_at}
        - optional index on {tenant_id, action}
    """
    db = get_database()
    token_coll = db["token_records"]
    await token_coll.create_index(
        [("tenant_id", 1), ("connection_id", 1), ("kind", 1)],
        unique=True,
        name="ux_tenant_conn_kind",
    )
    await token_coll.create_index(
        [("tenant_id", 1), ("kind", 1)],
        name="ix_tenant_kind",
    )

    audit_coll = db["audit_events"]
    await audit_coll.create_index(
        [("tenant_id", 1), ("created_at", -1)],
        name="ix_tenant_created_at",
    )
    await audit_coll.create_index(
        [("tenant_id", 1), ("action", 1)],
        name="ix_tenant_action",
    )
