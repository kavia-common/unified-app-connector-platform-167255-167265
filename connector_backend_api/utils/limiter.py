"""
Mongo-backed rate limit guard helper.

Uses RateLimitRepo.increment_and_get to atomically increase counters in a sliding-window bucket.
"""

from __future__ import annotations

from typing import Optional

from ..models.rate_limit import RateLimitRepo
from .errors import api_error_response, ErrorCode


# PUBLIC_INTERFACE
async def rate_limit_guard(
    tenant_id: str,
    connector_key: str,
    user_id: Optional[str] = None,
    window_sec: int = 60,
    limit: int = 60,
):
    """Increment usage, raise if exceeded."""
    rl = await RateLimitRepo().increment_and_get(
        tenant_id=tenant_id,
        connector_key=connector_key,
        user_id=user_id,
        window_sec=window_sec,
        limit=limit,
        increment=1,
    )
    if rl.count > rl.limit:
        raise api_error_response(ErrorCode.RATE_LIMIT, "Rate limit exceeded")
