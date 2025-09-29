from fastapi.testclient import TestClient
import pytest


def test_oauth_login_builds_url(client: TestClient):
    body = {
        "connector": "jira",
        "tenant_id": "tenant-test",
        "connection_id": "conn-1",
        "authorize_url": "https://auth.example.com/authorize",
        "client_id": "cid",
        "scopes": ["read", "write"],
      }
    r = client.post("/auth/oauth/login", json=body, headers={"x-tenant-id": "tenant-test"})
    assert r.status_code == 200
    data = r.json()
    assert "authorize_url" in data and "state" in data
    assert "client_id=cid" in data["authorize_url"]
    assert "scope=read%20write" in data["authorize_url"]
    assert "state=" in data["authorize_url"]


@pytest.fixture(autouse=True)
def patch_httpx_post(monkeypatch):
    # Patch httpx_post_with_retry called by callback/refresh
    from src.core import errors as err

    class Resp:
        def __init__(self, payload):
            self._payload = payload

        def json(self):
            return self._payload

    def fake_post(url, data=None, headers=None, timeout=None):
        # emulate token exchange or refresh results
        if data and data.get("grant_type") == "authorization_code":
            return Resp({"access_token": "at", "refresh_token": "rt", "expires_in": 3600})
        if data and data.get("grant_type") == "refresh_token":
            return Resp({"access_token": "new_at", "refresh_token": "new_rt", "expires_in": 7200})
        return Resp({})
    monkeypatch.setattr(err, "httpx_post_with_retry", fake_post)


def test_oauth_callback_success(client: TestClient):
    # state is built by patched encoder in conftest
    state = "state|tenant-test|conn-1|jira|fixed"
    headers = {
        "x-tenant-id": "tenant-test",
        "x-token-url": "https://auth.example.com/token",
        "x-client-id": "cid",
        "x-client-secret": "secret",
        "x-redirect-uri": "http://localhost:3000/oauth/callback",
    }
    r = client.get("/auth/oauth/callback", params={"code": "code123", "state": state}, headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert data["message"] == "OAuth successful"
    assert data["connection_id"] == "conn-1"
    assert data["tenant_id"] == "tenant-test"


def test_oauth_refresh_success(client: TestClient):
    # First, simulate that callback stored tokens by calling callback once
    state = "state|tenant-test|conn-1|jira|fixed"
    headers = {
        "x-tenant-id": "tenant-test",
        "x-token-url": "https://auth.example.com/token",
        "x-client-id": "cid",
        "x-client-secret": "secret",
        "x-redirect-uri": "http://localhost:3000/oauth/callback",
    }
    r1 = client.get("/auth/oauth/callback", params={"code": "code123", "state": state}, headers=headers)
    assert r1.status_code == 200

    body = {
        "tenant_id": "tenant-test",
        "connection_id": "conn-1",
        "token_url": "https://auth.example.com/token",
        "client_id": "cid",
        "client_secret": "secret",
        "extra": {},
    }
    r = client.post("/auth/oauth/refresh", json=body, headers={"x-tenant-id": "tenant-test"})
    assert r.status_code == 200
    data = r.json()
    assert data["message"] == "Token refreshed"


def test_apikey_set_and_verify(client: TestClient):
    # Set API key
    body_set = {
        "tenant_id": "tenant-test",
        "connection_id": "conn-1",
        "api_key": "supersecret",
        "header_name": "Authorization",
        "prefix": "Bearer",
    }
    r = client.post("/auth/apikey", json=body_set, headers={"x-tenant-id": "tenant-test"})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["message"] == "API key stored."

    # Verify correct
    body_verify = {
        "tenant_id": "tenant-test",
        "connection_id": "conn-1",
        "api_key": "supersecret",
    }
    r2 = client.post("/auth/apikey/verify", json=body_verify, headers={"x-tenant-id": "tenant-test"})
    assert r2.status_code == 200
    data2 = r2.json()
    assert data2["valid"] is True

    # Verify incorrect
    body_verify_bad = {
        "tenant_id": "tenant-test",
        "connection_id": "conn-1",
        "api_key": "not-correct",
    }
    r3 = client.post("/auth/apikey/verify", json=body_verify_bad, headers={"x-tenant-id": "tenant-test"})
    assert r3.status_code == 200
    data3 = r3.json()
    assert data3["valid"] is False
