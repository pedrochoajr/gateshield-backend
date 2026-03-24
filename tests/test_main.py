from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch

from gateway.main import app, EVENT_STORE

client = TestClient(app)


def setup_function():
    EVENT_STORE.clear()


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
    assert len(EVENT_STORE) == 1
    assert EVENT_STORE[0].decision in ["allow", "flag"]


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
    assert len(EVENT_STORE) == 1
    assert EVENT_STORE[0].decision == "block"

    mock_async_client.assert_not_called()