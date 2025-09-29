"""
Connectors package.

Exports:
- base: shared models and BaseConnector protocol
- jira: JiraConnector
- confluence: ConfluenceConnector
- registry: ConnectorRegistry and get_registry
"""

from .base import (  # noqa: F401
    ApiKeyConfig,
    AuthStrategy,
    Capability,
    ConnectorDescriptor,
    CreateRequest,
    CreateResponse,
    MetadataItem,
    MetadataRequest,
    MetadataResponse,
    OAuthConfig,
    SearchItem,
    SearchRequest,
    SearchResponse,
    BaseConnector,
)
from .jira import JiraConnector  # noqa: F401
from .confluence import ConfluenceConnector  # noqa: F401
from .registry import ConnectorRegistry, get_registry  # noqa: F401
