from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["status"] == "online"
    assert "metrics" in response.json()["endpoints"]

def test_metrics_dashboard():
    response = client.get("/api/metrics/dashboard")
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert "series" in response.json()
    assert "current" in response.json()
    assert len(response.json()["series"]) == 10
