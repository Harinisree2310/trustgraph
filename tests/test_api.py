
from fastapi.testclient import TestClient
from backend.app import app
client=TestClient(app)

def test_health():
    assert client.get("/api/health").status_code == 200

def test_demo_inventory_and_findings():
    assert client.get("/api/inventory").json()["count"] >= 1
    assert client.get("/api/findings").json()["count"] >= 1

def test_demo_reset():
    r=client.post("/api/demo/reset")
    assert r.status_code == 200
    assert r.json()["overview"]["packages"] >= 1
