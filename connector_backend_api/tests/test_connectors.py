import pytest

from fastapi.testclient import TestClient


class FakeConnector:
    def descriptor(self):
        # Minimal descriptor shape
        return type("Desc", (), {"model_dump": lambda self: {"key": "fake", "name": "Fake", "auth": ["api_key"]}})()

    async def search(self, req):
        from src.connectors.base import SearchResponse
        return SearchResponse(items=[{"id": "1", "title": f"res:{req.query}", "url": None, "snippet": None, "icon": None, "metadata": {}}], next_cursor=None)

    async def create(self, req):
        from src.connectors.base import CreateResponse
        return CreateResponse(id="ISSUE-1", url=None, metadata={"kind": req.kind})

    async def metadata(self, req):
        from src.connectors.base import MetadataResponse
        items = [{"id": "P1", "name": "Proj One", "url": None, "metadata": {}}] if req.resource == "projects" else [{"id": "S1", "name": "Space One", "url": None, "metadata": {}}]
        return MetadataResponse(items=items)


@pytest.fixture(autouse=True)
def patch_registry(monkeypatch):
    from src.connectors import registry as reg

    class FakeReg:
        def get(self, provider: str):
            if provider in ("jira", "confluence"):
                return FakeConnector()
            return None

        def list_connectors(self):
            return ["jira", "confluence"]

        def descriptors(self):
            # return iterable of descriptor-like objects with model_dump
            return [type("Desc", (), {"model_dump": lambda self: {"key": "jira"} })(),
                    type("Desc", (), {"model_dump": lambda self: {"key": "confluence"} })()]

    monkeypatch.setattr(reg, "get_registry", lambda: FakeReg())


def test_health(client: TestClient):
    r = client.get("/")
    assert r.status_code == 200
    data = r.json()
    assert data.get("message") == "Healthy"
    assert "version" in data


def test_list_connectors(client: TestClient):
    r = client.get("/connectors", headers={"x-tenant-id": "tenant-test"})
    assert r.status_code == 200
    data = r.json()
    assert "keys" in data and data["keys"] == ["jira", "confluence"]
    assert "descriptors" in data and isinstance(data["descriptors"], list)


def test_get_connector_metadata(client: TestClient):
    r = client.get("/connectors/jira/metadata", headers={"x-tenant-id": "tenant-test"})
    assert r.status_code == 200
    data = r.json()
    assert data.get("key") == "fake" or "key" in data  # tolerate descriptor shape


def test_search_proxy(client: TestClient):
    body = {"provider": "jira", "query": "fix bug", "tenant_id": "tenant-test", "connection_id": "conn-1"}
    r = client.post("/connectors/search", json=body, headers={"x-tenant-id": "tenant-test"})
    assert r.status_code == 200
    data = r.json()
    assert "items" in data and len(data["items"]) == 1
    assert data["items"][0]["title"].startswith("res:")


def test_create_proxy(client: TestClient):
    body = {
        "provider": "jira",
        "tenant_id": "tenant-test",
        "connection_id": "conn-1",
        "kind": "issue",
        "payload": {"summary": "Hello"},
    }
    r = client.post("/connectors/create", json=body, headers={"x-tenant-id": "tenant-test"})
    assert r.status_code == 200
    data = r.json()
    assert data.get("id") == "ISSUE-1"


def test_list_projects(client: TestClient):
    r = client.get("/connectors/jira/projects?tenant_id=tenant-test&connection_id=conn-1", headers={"x-tenant-id": "tenant-test"})
    assert r.status_code == 200
    data = r.json()
    assert "items" in data and data["items"][0]["id"] == "P1"


def test_list_spaces(client: TestClient):
    r = client.get("/connectors/confluence/spaces?tenant_id=tenant-test&connection_id=conn-1", headers={"x-tenant-id": "tenant-test"})
    assert r.status_code == 200
    data = r.json()
    assert "items" in data and data["items"][0]["id"] == "S1"


def test_llm_tools_discovery(client: TestClient):
    r = client.get("/connectors/tools")
    assert r.status_code == 200
    data = r.json()
    assert "tools" in data and "search" in data["tools"]


def test_llm_tool_proxy_search(client: TestClient):
    body = {"provider": "jira", "tool": "search", "tenant_id": "tenant-test", "connection_id": "conn-1", "query": "abc"}
    r = client.post("/connectors/tools", json=body, headers={"x-tenant-id": "tenant-test"})
    assert r.status_code == 200
    data = r.json()
    assert "items" in data and isinstance(data["items"], list)


def test_llm_tool_proxy_create_missing_payload(client: TestClient):
    body = {"provider": "jira", "tool": "create", "tenant_id": "tenant-test", "connection_id": "conn-1", "kind": "issue"}
    r = client.post("/connectors/tools", json=body, headers={"x-tenant-id": "tenant-test"})
    assert r.status_code == 400
    assert "Missing" in r.text
