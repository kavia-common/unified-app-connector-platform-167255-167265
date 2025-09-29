"""
Provider service layer for connectors.

This abstracts provider-specific logic, token access/refresh, and operations
like search/create/list_projects/list_spaces. Real implementations should call
the provider APIs (e.g., Atlassian Jira/Confluence APIs). Here we provide
skeletons with integration points, retry friendliness, and token access.

Environment variables:
- OAUTH_REDIRECT_BASE_URL: Base URL on backend to construct callback URLs, e.g., https://api.example.com/auth/oauth/callback
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import httpx

from ..models.user_token import UserTokenRepo, UserToken
from ..utils.errors import ApiError, ErrorCode


class ProviderServiceBase:
    """Base class for provider services."""

    provider: str
    key: str

    def __init__(self, tenant_id: str, token_repo: UserTokenRepo) -> None:
        self.tenant_id = tenant_id
        self.token_repo = token_repo

    # PUBLIC_INTERFACE
    async def oauth_authorization_url(self, user_id: str, scopes: Optional[List[str]], state: Optional[str]) -> str:
        """Return provider authorization URL. Implement in subclass."""
        raise NotImplementedError

    # PUBLIC_INTERFACE
    async def exchange_code_and_store_tokens(self, user_id: str, code: str, state: Optional[str]) -> None:
        """Exchange code for tokens and persist securely."""
        raise NotImplementedError

    # PUBLIC_INTERFACE
    async def validate_api_key(self, api_key: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Validate API key with provider; return ok and optional metadata."""
        raise NotImplementedError

    # PUBLIC_INTERFACE
    async def search(
        self, user_id: str, query: str, filters: Optional[Dict[str, Any]], limit: int
    ) -> List[Dict[str, Any]]:
        """Execute a search request and return uniform results."""
        raise NotImplementedError

    # PUBLIC_INTERFACE
    async def create(self, user_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Create an object in provider and return uniform response."""
        raise NotImplementedError

    # PUBLIC_INTERFACE
    async def list_projects(self, user_id: str) -> List[Dict[str, Any]]:
        """List projects for the provider."""
        return []

    # PUBLIC_INTERFACE
    async def list_spaces(self, user_id: str) -> List[Dict[str, Any]]:
        """List spaces for the provider."""
        return []

    async def _get_token(self, user_id: str, connector_key: str) -> Optional[UserToken]:
        tok = await self.token_repo.find_one(
            {"tenant_id": self.tenant_id, "user_id": user_id, "connector_key": connector_key}
        )
        return tok

    async def _ensure_valid_access_token(self, user_id: str, connector_key: str) -> Optional[UserToken]:
        tok = await self._get_token(user_id, connector_key)
        if not tok:
            return None

        # If expiry is close, attempt refresh routine (stub: not implemented fully)
        now = datetime.utcnow()
        if tok.expires_at and tok.expires_at < now + timedelta(minutes=2) and tok.refresh_token:
            # Implement refresh here for real provider flow.
            # For now we just simulate success by extending expiry.
            new_expiry = now + timedelta(hours=1)
            await self.token_repo.update_one(
                {"tenant_id": self.tenant_id, "user_id": user_id, "connector_key": connector_key},
                {"expires_at": new_expiry},
            )
            tok.expires_at = new_expiry
        return tok


class JiraConnectorService(ProviderServiceBase):
    provider = "atlassian"
    key = "jira"

    def __init__(self, tenant_id: str, token_repo: UserTokenRepo) -> None:
        super().__init__(tenant_id, token_repo)

    # PUBLIC_INTERFACE
    async def oauth_authorization_url(self, user_id: str, scopes: Optional[List[str]], state: Optional[str]) -> str:
        base = os.getenv("OAUTH_REDIRECT_BASE_URL") or ""
        # In real flow, use Atlassian OAuth authorize endpoint
        # Compose redirect_uri param using base and known callback route on frontend/back
        # This returns a mock URL suitable for development.
        return f"https://auth.atlassian.com/authorize?audience=api.atlassian.com&client_id=CLIENT&scope={'%20'.join(scopes or [])}&redirect_uri={base}/auth/oauth/callback&state={state or ''}&response_type=code&prompt=consent"

    # PUBLIC_INTERFACE
    async def exchange_code_and_store_tokens(self, user_id: str, code: str, state: Optional[str]) -> None:
        # Simulate token exchange; real implementation would call Atlassian OAuth token endpoint
        access_token = f"jira_access_{code}"
        refresh_token = f"jira_refresh_{code}"
        expires_at = datetime.utcnow() + timedelta(hours=1)
        await self.token_repo.upsert_token(
            tenant_id=self.tenant_id,
            user_id=user_id,
            connector_key=self.key,
            data={
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_at": expires_at,
                "scopes": ["read:jira-work", "write:jira-work"],
                "metadata": {"state": state},
            },
        )

    # PUBLIC_INTERFACE
    async def validate_api_key(self, api_key: str):
        # Jira does not typically use raw API key; treat as PAT and test
        # For now, stub validation as length check
        ok = len(api_key.strip()) > 20
        return ok, {"validated": ok}

    # PUBLIC_INTERFACE
    async def search(self, user_id: str, query: str, filters: Optional[Dict[str, Any]], limit: int):
        tok = await self._ensure_valid_access_token(user_id, self.key)
        if not tok or not (tok.access_token or tok.api_key):
            raise ApiError(ErrorCode.AUTH_REQUIRED, "No Jira token for user")
        # Stub search; return mock results
        items = []
        for i in range(min(limit, 10)):
            items.append(
                {
                    "id": f"JIRA-{100+i}",
                    "title": f"Jira issue result for '{query}' #{i}",
                    "url": f"https://jira.example.com/browse/JIRA-{100+i}",
                    "snippet": "Mock issue summary",
                    "meta": {"project": "JIRA", "status": "To Do"},
                }
            )
        return items

    # PUBLIC_INTERFACE
    async def create(self, user_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        tok = await self._ensure_valid_access_token(user_id, self.key)
        if not tok or not (tok.access_token or tok.api_key):
            raise ApiError(ErrorCode.AUTH_REQUIRED, "No Jira token for user")
        # Stub create; return mock id
        issue_id = "JIRA-5678"
        return {"id": issue_id, "url": f"https://jira.example.com/browse/{issue_id}", "meta": {"payload": payload}}

    # PUBLIC_INTERFACE
    async def list_projects(self, user_id: str) -> List[Dict[str, Any]]:
        tok = await self._ensure_valid_access_token(user_id, self.key)
        if not tok or not (tok.access_token or tok.api_key):
            raise ApiError(ErrorCode.AUTH_REQUIRED, "No Jira token for user")
        return [
            {"key": "JIRA", "name": "Jira Project"},
            {"key": "OPS", "name": "Operations"},
        ]


class ConfluenceConnectorService(ProviderServiceBase):
    provider = "atlassian"
    key = "confluence"

    def __init__(self, tenant_id: str, token_repo: UserTokenRepo) -> None:
        super().__init__(tenant_id, token_repo)

    # PUBLIC_INTERFACE
    async def oauth_authorization_url(self, user_id: str, scopes: Optional[List[str]], state: Optional[str]) -> str:
        base = os.getenv("OAUTH_REDIRECT_BASE_URL") or ""
        return f"https://auth.atlassian.com/authorize?audience=api.atlassian.com&client_id=CLIENT&scope={'%20'.join(scopes or [])}&redirect_uri={base}/auth/oauth/callback&state={state or ''}&response_type=code&prompt=consent"

    # PUBLIC_INTERFACE
    async def exchange_code_and_store_tokens(self, user_id: str, code: str, state: Optional[str]) -> None:
        access_token = f"confluence_access_{code}"
        refresh_token = f"confluence_refresh_{code}"
        expires_at = datetime.utcnow() + timedelta(hours=1)
        await self.token_repo.upsert_token(
            tenant_id=self.tenant_id,
            user_id=user_id,
            connector_key=self.key,
            data={
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_at": expires_at,
                "scopes": ["read:confluence-content", "write:confluence-content"],
                "metadata": {"state": state},
            },
        )

    # PUBLIC_INTERFACE
    async def validate_api_key(self, api_key: str):
        ok = len(api_key.strip()) > 20
        return ok, {"validated": ok}

    # PUBLIC_INTERFACE
    async def search(self, user_id: str, query: str, filters: Optional[Dict[str, Any]], limit: int):
        tok = await self._ensure_valid_access_token(user_id, self.key)
        if not tok or not (tok.access_token or tok.api_key):
            raise ApiError(ErrorCode.AUTH_REQUIRED, "No Confluence token for user")
        items = []
        for i in range(min(limit, 10)):
            items.append(
                {
                    "id": f"CONF-PAGE-{200+i}",
                    "title": f"Confluence page for '{query}' #{i}",
                    "url": f"https://confluence.example.com/pages/{200+i}",
                    "snippet": "Mock page excerpt",
                    "meta": {"space": "ENG"},
                }
            )
        return items

    # PUBLIC_INTERFACE
    async def create(self, user_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        tok = await self._ensure_valid_access_token(user_id, self.key)
        if not tok or not (tok.access_token or tok.api_key):
            raise ApiError(ErrorCode.AUTH_REQUIRED, "No Confluence token for user")
        page_id = "CONF-PAGE-999"
        return {"id": page_id, "url": f"https://confluence.example.com/pages/{page_id}", "meta": {"payload": payload}}

    # PUBLIC_INTERFACE
    async def list_spaces(self, user_id: str) -> List[Dict[str, Any]]:
        tok = await self._ensure_valid_access_token(user_id, self.key)
        if not tok or not (tok.access_token or tok.api_key):
            raise ApiError(ErrorCode.AUTH_REQUIRED, "No Confluence token for user")
        return [
            {"key": "ENG", "name": "Engineering"},
            {"key": "DESIGN", "name": "Design"},
        ]


# PUBLIC_INTERFACE
def get_provider_service(
    connector_key: str, provider: str, ctx, token_repo: UserTokenRepo
) -> ProviderServiceBase:
    """Factory to return the appropriate provider service implementation."""
    key = connector_key.lower()
    if key == "jira":
        return JiraConnectorService(ctx.tenant_id, token_repo)
    if key == "confluence":
        return ConfluenceConnectorService(ctx.tenant_id, token_repo)
    # Default stub for unknown connectors - could be extended to plugin loading
    raise ApiError(ErrorCode.CONNECTOR_NOT_FOUND, f"No service for connector '{connector_key}'")
