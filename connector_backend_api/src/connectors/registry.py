from __future__ import annotations

from typing import Dict, List, Optional

from src.connectors.base import BaseConnector, ConnectorDescriptor


class ConnectorRegistry:
    """
    Registry for connector providers.

    Supports:
    - Registration of connector instances
    - Lookup by key (e.g., "jira", "confluence")
    - Listing of available connectors/descriptors

    By default, this module registers the built-in connectors at import time.
    """

    def __init__(self) -> None:
        self._connectors: Dict[str, BaseConnector] = {}

    # PUBLIC_INTERFACE
    def register(self, connector: BaseConnector) -> None:
        """Register a connector instance by its key."""
        key = connector.key
        self._connectors[key] = connector

    # PUBLIC_INTERFACE
    def get(self, key: str) -> Optional[BaseConnector]:
        """Return a connector by key, or None if missing."""
        return self._connectors.get(key)

    # PUBLIC_INTERFACE
    def require(self, key: str) -> BaseConnector:
        """Return a connector by key, raising if not found."""
        conn = self.get(key)
        if not conn:
            raise KeyError(f"Connector '{key}' not found")
        return conn

    # PUBLIC_INTERFACE
    def list_connectors(self) -> List[str]:
        """List registered connector keys."""
        return sorted(self._connectors.keys())

    # PUBLIC_INTERFACE
    def descriptors(self) -> List[ConnectorDescriptor]:
        """Return connector descriptors for all registered connectors."""
        return [c.descriptor() for c in self._connectors.values()]


# Default registry instance
_registry = ConnectorRegistry()


def _register_builtin() -> None:
    """Register built-in connectors."""
    from src.connectors.jira import JiraConnector
    from src.connectors.confluence import ConfluenceConnector

    _registry.register(JiraConnector())
    _registry.register(ConfluenceConnector())


# initialize built-ins at import
_register_builtin()


# PUBLIC_INTERFACE
def get_registry() -> ConnectorRegistry:
    """Return the global connector registry instance."""
    return _registry
