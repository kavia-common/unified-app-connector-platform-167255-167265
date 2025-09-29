"""
Error handling, standardized error responses, in-memory rate limiting, and retry/backoff utilities.

This module provides:
- Error taxonomy via ErrorCode enum
- Pydantic models for standardized error responses (ErrorDetail, ErrorResponse)
- Custom exceptions mapped to HTTP responses (AppError, RateLimitExceeded, ProviderError, UnauthorizedError, NotFoundError, ValidationAppError)
- Centralized FastAPI exception handlers registration
- Simple in-memory rate limiter per (tenant_id, provider, route)
- Exponential backoff retry helpers for outbound HTTP calls (stubs wrapping httpx)

Notes:
- Rate limiting is in-memory; it resets on process restart and is per-instance.
- For distributed setups, replace with a shared store (e.g., Redis).
- All public interfaces have docstrings and PUBLIC_INTERFACE comments.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Optional, Tuple, TypeVar

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


class ErrorCode(str, Enum):
    """Standard error taxonomy for API responses."""
    BAD_REQUEST = "bad_request"
    VALIDATION_ERROR = "validation_error"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    RATE_LIMITED = "rate_limited"
    PROVIDER_ERROR = "provider_error"
    DEPENDENCY_ERROR = "dependency_error"
    INTERNAL_ERROR = "internal_error"


class ErrorDetail(BaseModel):
    """Fine-grained detail for an error."""
    field: Optional[str] = Field(default=None, description="Field or parameter associated with the error, if applicable.")
    message: str = Field(..., description="Human readable message.")
    code: Optional[str] = Field(default=None, description="Provider or domain-specific sub-code, if any.")


class ErrorResponse(BaseModel):
    """Standardized error response schema."""
    error: ErrorCode = Field(..., description="Categorized error code.")
    message: str = Field(..., description="Summary message.")
    request_id: Optional[str] = Field(default=None, description="Request correlation id (if available).")
    details: list[ErrorDetail] = Field(default_factory=list, description="Optional list of detailed errors.")
    meta: Dict[str, Any] = Field(default_factory=dict, description="Optional metadata for troubleshooting.")

    # PUBLIC_INTERFACE
    @staticmethod
    def from_exception(exc: Exception, default: Tuple[int, ErrorCode, str]) -> Tuple[int, "ErrorResponse"]:
        """
        Build a status code and ErrorResponse from an exception and default mapping.
        """
        status_code, default_code, default_msg = default
        if isinstance(exc, AppError):
            status_code = exc.status_code
            code = exc.code
            message = exc.message
            details = [ErrorDetail(field=d.get("field"), message=d.get("message"), code=d.get("code")) for d in exc.details]
            meta = exc.meta
        else:
            code = default_code
            message = default_msg
            details = []
            meta = {"exception": exc.__class__.__name__}
        return status_code, ErrorResponse(error=code, message=message, details=details, meta=meta)


class AppError(Exception):
    """Base application error with HTTP mapping."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 400,
        code: ErrorCode = ErrorCode.BAD_REQUEST,
        details: Optional[list[Dict[str, str]]] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.message = message
        self.status_code = status_code
        self.code = code
        self.details = details or []
        self.meta = meta or {}
        super().__init__(message)


class ValidationAppError(AppError):
    def __init__(self, message: str, details: Optional[list[Dict[str, str]]] = None, meta: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, status_code=422, code=ErrorCode.VALIDATION_ERROR, details=details, meta=meta)


class UnauthorizedError(AppError):
    def __init__(self, message: str = "Unauthorized", meta: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, status_code=401, code=ErrorCode.UNAUTHORIZED, meta=meta)


class ForbiddenError(AppError):
    def __init__(self, message: str = "Forbidden", meta: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, status_code=403, code=ErrorCode.FORBIDDEN, meta=meta)


class NotFoundError(AppError):
    def __init__(self, message: str = "Not found", meta: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, status_code=404, code=ErrorCode.NOT_FOUND, meta=meta)


class ConflictError(AppError):
    def __init__(self, message: str = "Conflict", meta: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, status_code=409, code=ErrorCode.CONFLICT, meta=meta)


class RateLimitExceeded(AppError):
    def __init__(self, message: str = "Too many requests", retry_after: Optional[int] = None, meta: Optional[Dict[str, Any]] = None) -> None:
        m = meta or {}
        if retry_after is not None:
            m["retry_after"] = retry_after
        super().__init__(message, status_code=429, code=ErrorCode.RATE_LIMITED, meta=m)


class ProviderError(AppError):
    def __init__(self, message: str = "Provider call failed", status_code: int = 502, meta: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, status_code=status_code, code=ErrorCode.PROVIDER_ERROR, meta=meta)


# ----- Centralized exception handlers -----

def _extract_request_id(req: Request) -> Optional[str]:
    # Common request id headers could be x-request-id or similar
    for h in ("x-request-id", "x-correlation-id", "x-amzn-trace-id"):
        if h in req.headers:
            return req.headers[h]
    return None

# PUBLIC_INTERFACE
def register_exception_handlers(app: FastAPI) -> None:
    """
    Register global exception handlers returning standardized ErrorResponse JSON.
    """

    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError):
        body = ErrorResponse(
            error=exc.code,
            message=exc.message,
            request_id=_extract_request_id(request),
            details=[ErrorDetail(field=d.get("field"), message=d.get("message"), code=d.get("code")) for d in exc.details],
            meta=exc.meta,
        )
        return JSONResponse(status_code=exc.status_code, content=body.model_dump())

    from fastapi.exceptions import RequestValidationError
    from starlette.exceptions import HTTPException as StarletteHTTPException

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        details = []
        try:
            for err in exc.errors():
                loc = ".".join(str(p) for p in err.get("loc", []))
                details.append(ErrorDetail(field=loc or None, message=err.get("msg", "Invalid value"), code=err.get("type")))
        except Exception:
            details = [ErrorDetail(message="Validation failed")]
        body = ErrorResponse(
            error=ErrorCode.VALIDATION_ERROR,
            message="Validation Error",
            request_id=_extract_request_id(request),
            details=[d for d in details],
            meta={},
        )
        return JSONResponse(status_code=422, content=body.model_dump())

    @app.exception_handler(StarletteHTTPException)
    async def starlette_http_handler(request: Request, exc: StarletteHTTPException):
        # Map known statuses to taxonomy
        mapping = {
            400: ErrorCode.BAD_REQUEST,
            401: ErrorCode.UNAUTHORIZED,
            403: ErrorCode.FORBIDDEN,
            404: ErrorCode.NOT_FOUND,
            409: ErrorCode.CONFLICT,
            429: ErrorCode.RATE_LIMITED,
            422: ErrorCode.VALIDATION_ERROR,
        }
        code = mapping.get(exc.status_code, ErrorCode.INTERNAL_ERROR)
        body = ErrorResponse(
            error=code,
            message=str(exc.detail) if exc.detail else "HTTP error",
            request_id=_extract_request_id(request),
            details=[],
            meta={},
        )
        return JSONResponse(status_code=exc.status_code, content=body.model_dump())

    @app.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc: Exception):
        status_code, err = ErrorResponse.from_exception(exc, default=(500, ErrorCode.INTERNAL_ERROR, "Internal Server Error"))
        err.request_id = _extract_request_id(request)
        return JSONResponse(status_code=status_code, content=err.model_dump())


# ----- In-memory Rate Limiter -----

@dataclass
class _Bucket:
    capacity: int
    window_seconds: int
    # map of window_start_epoch -> count
    window_start: int
    count: int


_rate_buckets: Dict[Tuple[str, str, str], _Bucket] = {}  # (tenant_id, provider, route) -> bucket

# PUBLIC_INTERFACE
def rate_limit_check(*, tenant_id: str, provider: str, route: str, capacity: int = 60, window_seconds: int = 60) -> None:
    """
    Check and enforce a simple fixed-window rate limit per (tenant, provider, route).
    Raises RateLimitExceeded if the limit is exceeded.
    """
    now = int(time.time())
    window_start = now - (now % window_seconds)
    key = (tenant_id or "unknown", provider or "unknown", route or "unknown")
    b = _rate_buckets.get(key)
    if b is None or b.window_start != window_start:
        b = _Bucket(capacity=capacity, window_seconds=window_seconds, window_start=window_start, count=0)
        _rate_buckets[key] = b
    if b.count >= b.capacity:
        retry_after = b.window_start + b.window_seconds - now
        raise RateLimitExceeded(retry_after=retry_after)
    b.count += 1


# ----- Retry with exponential backoff (httpx helper stubs) -----

T = TypeVar("T")

# PUBLIC_INTERFACE
async def async_retry(
    func: Callable[[], T | Any],
    *,
    retries: int = 3,
    base_delay: float = 0.5,
    max_delay: float = 4.0,
    retry_on_status: tuple[int, ...] = (429, 500, 502, 503, 504),
    retry_on_exceptions: tuple[type[BaseException], ...] = (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError, httpx.ConnectTimeout),
) -> T:
    """
    Execute a callable with retry and exponential backoff.
    For httpx responses, when the callable returns an httpx.Response and status is in retry_on_status,
    the call is retried. If the callable raises an exception matching retry_on_exceptions, retry as well.
    """
    attempt = 0
    delay = base_delay
    last_exc: Optional[BaseException] = None
    while attempt <= retries:
        try:
            result = await func() if asyncio.iscoroutinefunction(func) else func()
            # If result is Response, check status
            if isinstance(result, httpx.Response) and result.status_code in retry_on_status:
                raise ProviderError(
                    message=f"Upstream returned {result.status_code}",
                    status_code=502,
                    meta={"status": result.status_code, "body": result.text[:256]},
                )
            return result  # type: ignore[return-value]
        except ProviderError as e:
            last_exc = e
        except retry_on_exceptions as e:  # type: ignore[misc]
            last_exc = e
        except Exception as e:
            # Do not retry non-transient by default; bubble up.
            raise e
        attempt += 1
        if attempt > retries:
            break
        await asyncio.sleep(delay)
        delay = min(max_delay, delay * 2)
    # Exhausted
    if isinstance(last_exc, ProviderError):
        raise last_exc
    raise ProviderError("Provider call failed after retries", status_code=502, meta={"exception": str(last_exc) if last_exc else None})


# PUBLIC_INTERFACE
async def httpx_post_with_retry(
    url: str,
    *,
    client: Optional[httpx.AsyncClient] = None,
    **kwargs: Any,
) -> httpx.Response:
    """
    Perform httpx POST with retry/backoff on transient errors.
    """
    async def _do():
        if client is not None:
            return await client.post(url, **kwargs)
        async with httpx.AsyncClient(timeout=kwargs.pop("timeout", 20)) as c:
            return await c.post(url, **kwargs)
    return await async_retry(_do)


# PUBLIC_INTERFACE
async def httpx_get_with_retry(
    url: str,
    *,
    client: Optional[httpx.AsyncClient] = None,
    **kwargs: Any,
) -> httpx.Response:
    """
    Perform httpx GET with retry/backoff on transient errors.
    """
    async def _do():
        if client is not None:
            return await client.get(url, **kwargs)
        async with httpx.AsyncClient(timeout=kwargs.pop("timeout", 20)) as c:
            return await c.get(url, **kwargs)
    return await async_retry(_do)
