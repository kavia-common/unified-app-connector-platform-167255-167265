"""
Security helpers for JWT-based OAuth state encoding/decoding and API key hashing.

- JWT is used to sign and verify oauth state query parameter.
- API key hashing uses HMAC with a salt and configured algorithm.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from typing import Any, Dict

import jwt  # PyJWT

from src.core.config import get_settings


# PUBLIC_INTERFACE
def encode_oauth_state(payload: Dict[str, Any]) -> str:
    """
    Encode and sign an OAuth state payload as a JWT.

    Parameters:
        payload: dictionary data to include in the state (must be JSON serializable)

    Returns:
        A compact JWT string.
    """
    settings = get_settings()
    now = int(time.time())
    exp = now + int(settings.JWT_STATE_TTL_SECONDS)
    to_encode = {"iat": now, "exp": exp, **payload}
    token = jwt.encode(to_encode, settings.JWT_STATE_SECRET, algorithm=settings.JWT_ALGORITHM)
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


# PUBLIC_INTERFACE
def decode_oauth_state(token: str) -> Dict[str, Any]:
    """
    Decode and verify an OAuth state JWT.

    Parameters:
        token: JWT string to decode

    Returns:
        Decoded payload as a dictionary.
    """
    settings = get_settings()
    data = jwt.decode(token, settings.JWT_STATE_SECRET, algorithms=[settings.JWT_ALGORITHM])
    assert isinstance(data, dict)
    return data


def _derive_key(secret: str, salt: str) -> bytes:
    # Simple derivation combining secret and salt; can be replaced with PBKDF2/argon2 in future.
    return hashlib.sha256(f"{secret}:{salt}".encode("utf-8")).digest()


# PUBLIC_INTERFACE
def hash_api_key(plaintext_api_key: str) -> str:
    """
    Hash an API key using HMAC and configured salt/algorithm.

    Returns:
        base64-encoded digest string safe to store in DB.
    """
    settings = get_settings()
    key = _derive_key(settings.API_KEY_HASH_SALT, settings.API_KEY_HASH_ALGORITHM)
    digest = hmac.new(key, plaintext_api_key.encode("utf-8"), getattr(hashlib, settings.API_KEY_HASH_ALGORITHM)).digest()
    return base64.b64encode(digest).decode("utf-8")


# PUBLIC_INTERFACE
def verify_api_key(plaintext_api_key: str, stored_hash_b64: str) -> bool:
    """
    Verify a provided API key against a stored base64-encoded hash.

    Returns:
        True if matches, else False.
    """
    try:
        computed = hash_api_key(plaintext_api_key)
        return hmac.compare_digest(computed, stored_hash_b64)
    except Exception:
        return False
