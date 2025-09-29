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


class JiraConnector(BaseConnector):
    """
    Jira connector implementation skeleton.

    Notes:
    - Uses Atlassian Cloud Jira APIs. Base URL typically 'https://your-domain.atlassian.net'.
    - For OAuth, the 'access_token' is used as Bearer token.
    - For API key, Atlassian often uses basic auth with email:API_TOKEN, but for simplicity, we support a header-based API key.
      If you prefer basic auth, transform the headers accordingly in apply_auth.
    """

    key: str = "jira"
    name: str = "Jira"

    # PUBLIC_INTERFACE
    def descriptor(self) -> ConnectorDescriptor:
        """Return connector descriptor including capabilities and auth support."""
        return ConnectorDescriptor(
            key=self.key,
            name=self.name,
            auth_supported=[AuthStrategy.OAUTH, AuthStrategy.API_KEY],
            capabilities=[Capability.SEARCH, Capability.CREATE, Capability.METADATA],
            docs_url=HttpUrl("https://developer.atlassian.com/cloud/jira/platform/rest/v3/intro/", scheme="https"),
            website_url=HttpUrl("https://www.atlassian.com/software/jira", scheme="https"),
            icon="/assets/icons/jira.svg",
        )

    # PUBLIC_INTERFACE
    def auth_strategies(self) -> List[AuthStrategy]:
        return [AuthStrategy.OAUTH, AuthStrategy.API_KEY]

    # PUBLIC_INTERFACE
    def apply_auth(self, headers: Dict[str, str], *, auth: Dict[str, Any]) -> Dict[str, str]:
        """
        Apply auth headers.

        Expected auth dict:
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
        Execute Jira search (JQL or text). This is a stub that returns a shaped response.

        In a real implementation, construct the JQL and call:
        GET {base_url}/rest/api/3/search?jql=...
        """
        # Placeholder logic
        q = req.query.strip()
        items: List[SearchItem] = []
        if q:
            items.append(
                SearchItem(
                    id="JIRA-123",
                    title=f"Sample issue matching '{q}'",
                    url=HttpUrl("https://example.atlassian.net/browse/JIRA-123", scheme="https"),
                    snippet="This is a stub result for demonstration.",
                    icon="/assets/icons/jira.svg",
                    metadata={"projectKey": "JIRA", "issueType": "Task"},
                )
            )
        return SearchResponse(items=items, next_cursor=None)

    # PUBLIC_INTERFACE
    async def create(self, req: CreateRequest) -> CreateResponse:
        """
        Create a Jira entity (typically an issue). This is a stub with expected return shape.

        In a real implementation, POST to:
        {base_url}/rest/api/3/issue
        with payload mapped from req.payload
        """
        # Validate kind and payload minimal structure
        if req.kind not in {"issue"}:
            raise ValueError("Unsupported Jira create kind, expected 'issue'")
        issue_key = "JIRA-999"
        return CreateResponse(
            id=issue_key,
            url=HttpUrl(f"https://example.atlassian.net/browse/{issue_key}", scheme="https"),
            metadata={"created": True, "kind": req.kind},
        )

    # PUBLIC_INTERFACE
    async def metadata(self, req: MetadataRequest) -> MetadataResponse:
        """
        List Jira projects/spaces (spaces not applicable to Jira; spaces are Confluence).
        For this stub, we support 'projects' only.
        """
        if req.resource == "projects":
            items = [
                MetadataItem(
                    id="10000",
                    key="JIRA",
                    name="Jira Software",
                    url=HttpUrl("https://example.atlassian.net/jira/projects/JIRA", scheme="https"),
                    metadata={"lead": "owner@example.com"},
                )
            ]
            return MetadataResponse(items=items)
        # If spaces requested for Jira, return empty or raise
        return MetadataResponse(items=[])
