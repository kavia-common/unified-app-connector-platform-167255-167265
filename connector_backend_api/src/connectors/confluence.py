from __future__ import annotations

from typing import Any, Dict, List

from pydantic import HttpUrl

from src.connectors.base import (
    AuthStrategy,
    Capability,
    ConnectorDescriptor,
    CreateRequest,
    CreateResponse,
    MetadataItem,
    MetadataRequest,
    MetadataResponse,
    SearchItem,
    SearchRequest,
    SearchResponse,
    BaseConnector,
    ensure_prefix,
    merge_headers,
)


class ConfluenceConnector(BaseConnector):
    """
    Confluence connector implementation skeleton.

    Notes:
    - Atlassian Cloud Confluence base URL typically 'https://your-domain.atlassian.net/wiki'.
    - OAuth: Bearer token; API key: support configurable header or Bearer by default.
    """

    key: str = "confluence"
    name: str = "Confluence"

    # PUBLIC_INTERFACE
    def descriptor(self) -> ConnectorDescriptor:
        return ConnectorDescriptor(
            key=self.key,
            name=self.name,
            auth_supported=[AuthStrategy.OAUTH, AuthStrategy.API_KEY],
            capabilities=[Capability.SEARCH, Capability.CREATE, Capability.METADATA],
            docs_url=HttpUrl("https://developer.atlassian.com/cloud/confluence/rest/v2/intro/", scheme="https"),
            website_url=HttpUrl("https://www.atlassian.com/software/confluence", scheme="https"),
            icon="/assets/icons/confluence.svg",
        )

    # PUBLIC_INTERFACE
    def auth_strategies(self) -> List[AuthStrategy]:
        return [AuthStrategy.OAUTH, AuthStrategy.API_KEY]

    # PUBLIC_INTERFACE
    def apply_auth(self, headers: Dict[str, str], *, auth: Dict[str, Any]) -> Dict[str, str]:
        """
        Expected:
        - {'kind': 'oauth', 'access_token': '...'}
        - {'kind': 'api_key', 'api_key': '...', 'header_name'?: 'Authorization', 'prefix'?: 'Bearer'}
        """
        kind = auth.get("kind")
        if kind == "oauth":
            token = auth.get("access_token")
            if not token:
                raise ValueError("Missing access_token for OAuth")
            return merge_headers(headers, {"Authorization": f"Bearer {token}"})
        elif kind == "api_key":
            api_key = auth.get("api_key")
            if not api_key:
                raise ValueError("Missing api_key for API Key auth")
            header_name = auth.get("header_name", "Authorization")
            prefix = auth.get("prefix", "Bearer")
            return merge_headers(headers, {header_name: ensure_prefix(api_key, prefix)})
        else:
            raise ValueError("Unsupported auth.kind")

    # PUBLIC_INTERFACE
    async def search(self, req: SearchRequest) -> SearchResponse:
        """
        Execute Confluence search for content/pages (stub).

        Real call example:
        GET {base_url}/wiki/api/v2/search?cql=...
        """
        q = req.query.strip()
        items: List[SearchItem] = []
        if q:
            items.append(
                SearchItem(
                    id="123456",
                    title=f"Sample Confluence page for '{q}'",
                    url=HttpUrl("https://example.atlassian.net/wiki/spaces/SPACE/pages/123456", scheme="https"),
                    snippet="Stub content preview from Confluence.",
                    icon="/assets/icons/confluence.svg",
                    metadata={"spaceKey": "SPACE", "type": "page"},
                )
            )
        return SearchResponse(items=items, next_cursor=None)

    # PUBLIC_INTERFACE
    async def create(self, req: CreateRequest) -> CreateResponse:
        """
        Create Confluence content such as 'page' (stub).

        Real call example:
        POST {base_url}/wiki/api/v2/pages
        """
        if req.kind not in {"page"}:
            raise ValueError("Unsupported Confluence create kind, expected 'page'")
        page_id = "987654"
        return CreateResponse(
            id=page_id,
            url=HttpUrl(f"https://example.atlassian.net/wiki/spaces/SPACE/pages/{page_id}", scheme="https"),
            metadata={"created": True, "kind": req.kind},
        )

    # PUBLIC_INTERFACE
    async def metadata(self, req: MetadataRequest) -> MetadataResponse:
        """
        List Confluence spaces (supports 'spaces' resource).
        """
        if req.resource == "spaces":
            items = [
                MetadataItem(
                    id="SPACE",
                    key="SPACE",
                    name="Team Space",
                    url=HttpUrl("https://example.atlassian.net/wiki/spaces/SPACE", scheme="https"),
                    metadata={"type": "global"},
                )
            ]
            return MetadataResponse(items=items)
        return MetadataResponse(items=[])
