from fastapi.testclient import TestClient


def test_oauth_callback_missing_state_returns_422(client: TestClient):
    # FastAPI validation should 422 when required 'state' query is missing
    r = client.get("/auth/oauth/callback", params={"code": "abc"}, headers={"x-tenant-id": "tenant-test"})
    assert r.status_code == 422


def test_oauth_callback_provider_error_is_generic_message(client: TestClient):
    headers = {"x-tenant-id": "tenant-test"}
    r = client.get(
        "/auth/oauth/callback",
        params={"state": "state|tenant-test|conn-1|jira|fixed", "error": "access_denied", "error_description": "raw provider details"},
        headers=headers,
    )
    assert r.status_code == 400
    # ensure generic message, not echo error_description
    assert "Provider returned an error" in r.text
    assert "raw provider details" not in r.text


def test_oauth_refresh_without_prior_callback_returns_404(client: TestClient):
    # No refresh token stored should yield 404
    body = {
        "tenant_id": "tenant-test",
        "connection_id": "no-such-conn",
        "token_url": "https://auth.example.com/token",
        "client_id": "cid",
        "client_secret": "secret",
    }
    r = client.post("/auth/oauth/refresh", json=body, headers={"x-tenant-id": "tenant-test"})
    assert r.status_code == 404
    assert "No refresh token stored" in r.text


def test_apikey_verify_without_stored_key_returns_404(client: TestClient):
    body_verify = {"tenant_id": "tenant-test", "connection_id": "conn-missing", "api_key": "anything"}
    r = client.post("/auth/apikey/verify", json=body_verify, headers={"x-tenant-id": "tenant-test"})
    assert r.status_code == 404
    assert "No API key stored" in r.text
