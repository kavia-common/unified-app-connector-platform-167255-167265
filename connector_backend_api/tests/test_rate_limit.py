from fastapi.testclient import TestClient


def test_rate_limit_on_oauth_login_returns_429_when_exceeded(monkeypatch):
    # Construct a raw client to avoid patched tenant context rate limit bypass. We still need a tenant id header.
    from src.api.main import app
    client = TestClient(app)
    # Use small limit by temporarily wrapping the limiter.limit decorator call to simulate being already over limit.
    # However, slowapi maintains in-memory counters; easiest way is to make repeated calls over the default limits set in code.
    body = {
        "connector": "jira",
        "tenant_id": "tenant-test",
        "connection_id": "conn-rl",
        "authorize_url": "https://auth.example.com/authorize",
        "client_id": "cid",
        "scopes": ["read"],
    }
    headers = {"x-tenant-id": "tenant-test"}

    # Make multiple calls to trigger limit "15/minute". 20 attempts should cross it.
    too_many = None
    for i in range(25):
        r = client.post("/auth/oauth/login", json=body, headers=headers)
        if r.status_code == 429:
            too_many = r
            break

    assert too_many is not None, "Did not hit 429 after many requests; investigate limiter wiring"
    assert too_many.status_code == 429
    # Ensure sanitized body message
    assert "Too many requests" in too_many.text


def test_rate_limit_on_tools_proxy_search(monkeypatch):
    from src.api.main import app
    client = TestClient(app)
    headers = {"x-tenant-id": "tenant-test"}
    body = {
        "provider": "jira",
        "tool": "search",
        "tenant_id": "tenant-test",
        "connection_id": "conn-rl2",
        "query": "abc",
    }
    # 60/minute on /connectors/search path, but tools endpoint relies on custom rate_limit_check and does not use slowapi decorator.
    # Make sure endpoint still functions and isn't 429 here (custom check is patched to noop in conftest).
    r = client.post("/connectors/tools", json=body, headers=headers)
    assert r.status_code == 200
