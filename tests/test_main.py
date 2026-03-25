from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch

from gateway.main import app
from gateway.database.db import clear_events

client = TestClient(app)


def setup_function():
    clear_events()


def test_safe_request_is_forwarded():
    mock_response = AsyncMock()
    mock_response.content = b'{"results":["ok"]}'
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "application/json"}

    mock_client = AsyncMock()
    mock_client.__aenter__.return_value.request.return_value = mock_response

    with patch("gateway.main.httpx.AsyncClient", return_value=mock_client):
        response = client.post(
            "/search",
            json={"query": "laptop"},
            headers={"Authorization": "Bearer token"},
        )

    assert response.status_code == 200
    assert response.json() == {"results": ["ok"]}

    events_response = client.get("/events")
    assert events_response.status_code == 200

    payload = events_response.json()
    assert payload["summary"]["total"] == 1
    assert payload["summary"]["block"] == 0
    assert len(payload["events"]) == 1
    assert payload["events"][0]["decision"] in ["allow", "flag"]
    assert payload["events"][0]["path"] == "/search"
    assert isinstance(payload["events"][0]["query_params"], dict)
    assert isinstance(payload["events"][0]["rule_matches"], list)


def test_malicious_request_is_blocked():
    with patch("gateway.main.httpx.AsyncClient") as mock_async_client:
        response = client.post(
            "/login",
            json={"username": "admin", "password": "' OR 1=1 --"},
        )

    assert response.status_code == 403
    body = response.json()

    assert body["message"] == "Request blocked by GateShield"
    assert body["risk_score"] >= 60

    events_response = client.get("/events")
    assert events_response.status_code == 200

    payload = events_response.json()
    assert payload["summary"]["total"] == 1
    assert payload["summary"]["block"] == 1
    assert len(payload["events"]) == 1
    assert payload["events"][0]["decision"] == "block"
    assert payload["events"][0]["path"] == "/login"

    mock_async_client.assert_not_called()


def test_events_filter_by_decision():
    with patch("gateway.main.httpx.AsyncClient") as mock_async_client:
        response = client.post(
            "/login",
            json={"username": "admin", "password": "' OR 1=1 --"},
        )
    assert response.status_code == 403
    mock_async_client.assert_not_called()

    filtered = client.get("/events?decision=block")
    assert filtered.status_code == 200

    payload = filtered.json()
    assert payload["summary"]["total"] == 1
    assert len(payload["events"]) == 1
    assert payload["events"][0]["decision"] == "block"


def test_events_summary_endpoint():
    summary_response = client.get("/events/summary")
    assert summary_response.status_code == 200

    payload = summary_response.json()
    assert "total" in payload
    assert "allow" in payload
    assert "flag" in payload
    assert "block" in payload