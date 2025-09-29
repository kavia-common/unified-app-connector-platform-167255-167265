"""
Base connector interface to be implemented by specific connectors (e.g., Jira, Confluence).
"""

from __future__ import annotations

from typing import Any, Dict, List, Protocol


class BaseConnector(Protocol):
    """
    Interface for connector implementations.

    Concrete connectors should implement interaction methods with their external services.
    This is intentionally minimal for the initial foundation and will be expanded later.
    """

    name: str

    # PUBLIC_INTERFACE
    async def search(self, query: str, *, tenant_id: str, connection_id: str, **kwargs: Any) -> List[Dict[str, Any]]:
        """Search remote system for query string and return a list of results."""
        ...

    # PUBLIC_INTERFACE
    async def create(self, payload: Dict[str, Any], *, tenant_id: str, connection_id: str, **kwargs: Any) -> Dict[str, Any]:
        """Create an entity in the remote system based on payload and return created resource info."""
        ...
