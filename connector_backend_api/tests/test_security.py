import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def bare_client() -> TestClient:
    # Use the same app but avoid auto fixtures overriding tenant context for negative tests
    from src.api.main import app
    return TestClient(app)


def test_missing_tenant_header_on_connectors_search_returns_400(bare_client: TestClient):
    # No x-tenant-id header and no Authorization -> get_tenant_context should 400 for missing tenant identifier
    body = {
        "provider": "jira",
        "query": "test",
        "tenant_id": "tenant-test",  # route-provided exists but header context missing -> still requires context determine tenant
        "connection_id": "conn-1",
    }
    r = bare_client.post("/connectors/search", json=body)
    # get_tenant_context uses DEFAULT_TENANT_ID if set. In tests it's not set; should raise 400
    assert r.status_code in (400, 403), r.text


def test_tenant_mismatch_forbidden(client: TestClient):
    # client fixture patches a static TenantContext with tenant-test
    # Provide body with a different tenant to trigger enforce_tenant_match -> 403
    body = {
        "provider": "jira",
        "query": "test",
        "tenant_id": "another-tenant",
        "connection_id": "conn-1",
    }
    r = client.post("/connectors/search", json=body, headers={"x-tenant-id": "tenant-test"})
    assert r.status_code == 403
    assert "Tenant access denied" in r.text


def test_authorization_header_malformed_token_is_ignored(client: TestClient):
    # get_tenant_context should not crash on bad JWT; it swallows errors and proceeds with tenant header
    body = {
        "provider": "jira",
        "query": "ok",
        "tenant_id": "tenant-test",
        "connection_id": "conn-1",
    }
    headers = {
        "x-tenant-id": "tenant-test",
        "Authorization": "Bearer not-a-real-jwt"
    }
    r = client.post("/connectors/search", json=body, headers=headers)
    # Should still succeed given the rest of the pipeline is patched via test fixtures
    assert r.status_code == 200


def test_invalid_tool_name_returns_400(client: TestClient):
    body = {
        "provider": "jira",
        "tool": "unknown-tool",
        "tenant_id": "tenant-test",
        "connection_id": "conn-1",
    }
    r = client.post("/connectors/tools", json=body, headers={"x-tenant-id": "tenant-test"})
    assert r.status_code == 400
    assert "Unsupported tool" in r.text


def test_connectors_metadata_unknown_provider_returns_404(client: TestClient):
    r = client.get("/connectors/unknown/metadata", headers={"x-tenant-id": "tenant-test"})
    assert r.status_code in (404, 422)  # 422 if path validation, but our router raises NotFoundError -> 404
