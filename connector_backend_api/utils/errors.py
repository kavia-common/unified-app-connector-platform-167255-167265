"""
Error taxonomy and standardized response helpers.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import HTTPException, status
from pydantic import BaseModel


class ErrorCode:
    BAD_REQUEST = "bad_request"
    UNAUTHORIZED = "unauthorized"
    AUTH_REQUIRED = "auth_required"
    AUTH_INVALID = "auth_invalid"
    CONNECTOR_NOT_FOUND = "connector_not_found"
    RATE_LIMIT = "rate_limit_exceeded"
    BAD_GATEWAY = "bad_gateway"
    INTERNAL_ERROR = "internal_error"


class ApiError(Exception):
    """Logical error that maps to an error code."""

    # PUBLIC_INTERFACE
    def __init__(self, code: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


# PUBLIC_INTERFACE
def standard_response(data: Any, status_text: str = "ok") -> Dict[str, Any]:
    """Wrap responses into a frontend-friendly envelope."""
    return {"status": status_text, "data": data}


# PUBLIC_INTERFACE
def api_error_response(code: str, message: str, http_status: Optional[int] = None) -> HTTPException:
    """Create an HTTPException with standardized error body."""
    status_map = {
        ErrorCode.BAD_REQUEST: status.HTTP_400_BAD_REQUEST,
        ErrorCode.UNAUTHORIZED: status.HTTP_401_UNAUTHORIZED,
        ErrorCode.AUTH_REQUIRED: status.HTTP_401_UNAUTHORIZED,
        ErrorCode.AUTH_INVALID: status.HTTP_401_UNAUTHORIZED,
        ErrorCode.CONNECTOR_NOT_FOUND: status.HTTP_404_NOT_FOUND,
        ErrorCode.RATE_LIMIT: status.HTTP_429_TOO_MANY_REQUESTS,
        ErrorCode.BAD_GATEWAY: status.HTTP_502_BAD_GATEWAY,
        ErrorCode.INTERNAL_ERROR: status.HTTP_500_INTERNAL_SERVER_ERROR,
    }
    code_status = status_map.get(code, status.HTTP_400_BAD_REQUEST)
    http_code = http_status or code_status
    return HTTPException(
        status_code=http_code,
        detail={"status": "error", "error": {"code": code, "message": message}},
    )
