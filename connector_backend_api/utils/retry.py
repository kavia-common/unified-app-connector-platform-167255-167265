"""
Async retry with exponential backoff and jitter for external API calls.
"""

from __future__ import annotations

import asyncio
import random
from typing import Awaitable, Callable, TypeVar

T = TypeVar("T")


# PUBLIC_INTERFACE
async def retry_async(
    fn: Callable[[], Awaitable[T]],
    retries: int = 3,
    base_delay: float = 0.5,
    max_delay: float = 5.0,
) -> T:
    """Execute fn with retries and exponential backoff with jitter."""
    attempt = 0
    while True:
        try:
            return await fn()
        except Exception:
            if attempt >= retries:
                raise
            sleep_for = min(max_delay, base_delay * (2 ** attempt)) + random.random() * 0.2
            await asyncio.sleep(sleep_for)
            attempt += 1
