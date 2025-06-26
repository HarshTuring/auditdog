from fastapi.testclient import TestClient
from app.main import app

def test_health_check():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_root_endpoint():
    client = TestClient(app)
    response = client.get("/api/v1/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data and "AuditDog" in data["message"]
    assert data["status"] == "operational"

def test_list_events():
    client = TestClient(app)
    response = client.get("/api/v1/ssh/events")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_post_events_validation():
    client = TestClient(app)
    response = client.post("/api/v1/ssh/events", json={})
    assert response.status_code == 422  # Unprocessable Entity due to missing required fields