from __future__ import annotations

from fastapi import APIRouter

from src.connectors.registry import get_registry

router = APIRouter(prefix="/connectors", tags=["connectors"])

@router.get(
    "",
    summary="List registered connectors",
    description="Returns the list of registered connector keys and their descriptors.",
    response_description="An object containing connector keys and descriptors.",
)
def list_connectors():
    """
    PUBLIC_INTERFACE
    List available connectors.

    Returns:
        JSON with keys and descriptors.
    """
    reg = get_registry()
    return {"keys": reg.list_connectors(), "descriptors": [d.model_dump() for d in reg.descriptors()]}
