import os
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app, rate_limit_state


client = TestClient(app)

# Use the API key configured for the local test environment.
TEST_API_KEY = os.getenv(
    "API_KEY",
    "GeloCodes-PortScanner-2026"
)

# Headers used by authenticated test requests.
AUTH_HEADERS = {
    "X-API-Key": TEST_API_KEY
}


def setup_function():
    """
    Clear the in-memory rate-limit state before each test.

    This prevents requests from one test affecting another test.
    """

    rate_limit_state.clear()


def test_root_endpoint():
    """
    Verify that the API health-check endpoint works.
    """

    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {
        "message": "Port Scanner API is running"
    }


@patch("app.main.scan_ports")
def test_scan_endpoint_returns_scan_results(mock_scan_ports):
    """
    Verify that the /scan endpoint accepts a valid authenticated
    request and returns the scanner results.
    """

    mock_scan_ports.return_value = [
        {
            "port": 80,
            "service": "http"
        },
        {
            "port": 443,
            "service": "https"
        }
    ]

    response = client.post(
        "/scan",
        headers=AUTH_HEADERS,
        json={
            "target": "127.0.0.1",
            "start_port": 1,
            "end_port": 100
        }
    )

    assert response.status_code == 200

    response_data = response.json()

    assert response_data["target"] == "127.0.0.1"
    assert response_data["resolved_ip"] == "127.0.0.1"
    assert response_data["scanned_ports"] == 100
    assert response_data["open_ports"] == [
        {
            "port": 80,
            "service": "http"
        },
        {
            "port": 443,
            "service": "https"
        }
    ]

    # Verify that scan timing information is included.
    assert "scan_time_seconds" in response_data
    assert response_data["scan_time_seconds"] >= 0


def test_scan_endpoint_rejects_missing_api_key():
    """
    Verify that the /scan endpoint rejects requests that do not
    provide an API key.
    """

    response = client.post(
        "/scan",
        json={
            "target": "127.0.0.1",
            "start_port": 1,
            "end_port": 100
        }
    )

    assert response.status_code == 401
    assert response.json() == {
        "detail": "Invalid or missing API key."
    }


def test_scan_endpoint_rejects_invalid_api_key():
    """
    Verify that the /scan endpoint rejects an incorrect API key.
    """

    response = client.post(
        "/scan",
        headers={
            "X-API-Key": "incorrect-api-key"
        },
        json={
            "target": "127.0.0.1",
            "start_port": 1,
            "end_port": 100
        }
    )

    assert response.status_code == 401
    assert response.json() == {
        "detail": "Invalid or missing API key."
    }


def test_scan_endpoint_rejects_invalid_port_range():
    """
    Verify that the API rejects a request where the starting
    port is greater than the ending port.
    """

    response = client.post(
        "/scan",
        headers=AUTH_HEADERS,
        json={
            "target": "127.0.0.1",
            "start_port": 500,
            "end_port": 100
        }
    )

    assert response.status_code == 400
    assert response.json() == {
        "detail": "start_port must be less than or equal to end_port."
    }


def test_scan_endpoint_rejects_excessive_scan_range():
    """
    Verify that the API rejects a scan request that exceeds
    the configured maximum number of ports.
    """

    response = client.post(
        "/scan",
        headers=AUTH_HEADERS,
        json={
            "target": "127.0.0.1",
            "start_port": 1,
            "end_port": 5001
        }
    )

    assert response.status_code == 400
    assert response.json() == {
        "detail": "Scan range cannot exceed 5000 ports."
    }


def test_scan_endpoint_rejects_unauthorised_target():
    """
    Verify that the API rejects a target that is not included
    in the authorised target allowlist.
    """

    response = client.post(
        "/scan",
        headers=AUTH_HEADERS,
        json={
            "target": "example.com",
            "start_port": 1,
            "end_port": 10
        }
    )

    assert response.status_code == 403
    assert response.json() == {
        "detail": "Target is not authorised for scanning."
    }


def test_scan_endpoint_rejects_unresolvable_authorised_target():
    """
    Verify that the API returns an error when an authorised
    target cannot be resolved.
    """

    with patch(
        "app.main.socket.gethostbyname",
        side_effect=__import__("socket").gaierror
    ):
        response = client.post(
            "/scan",
            headers=AUTH_HEADERS,
            json={
                "target": "127.0.0.1",
                "start_port": 1,
                "end_port": 10
            }
        )

    assert response.status_code == 400
    assert response.json() == {
        "detail": "Target hostname could not be resolved."
    }


def test_scan_endpoint_rejects_invalid_port_numbers():
    """
    Verify that FastAPI validation rejects ports outside
    the valid TCP port range of 1 through 65535.
    """

    response = client.post(
        "/scan",
        headers=AUTH_HEADERS,
        json={
            "target": "127.0.0.1",
            "start_port": 0,
            "end_port": 70000
        }
    )

    assert response.status_code == 422


def test_scan_endpoint_requires_target():
    """
    Verify that the target field is required.
    """

    response = client.post(
        "/scan",
        headers=AUTH_HEADERS,
        json={
            "start_port": 1,
            "end_port": 100
        }
    )

    assert response.status_code == 422


@patch("app.main.scan_ports")
def test_scan_endpoint_enforces_rate_limit(mock_scan_ports):
    """
    Verify that the API blocks a client after the configured
    number of requests within the rate-limit window.
    """

    # Prevent the test from performing real port scans.
    mock_scan_ports.return_value = []

    # Temporarily reduce the limit so the test only needs
    # three requests instead of making ten or more requests.
    with patch(
        "app.main.get_rate_limit_requests",
        return_value=2
    ):
        # First request should be accepted.
        first_response = client.post(
            "/scan",
            headers=AUTH_HEADERS,
            json={
                "target": "127.0.0.1",
                "start_port": 1,
                "end_port": 10
            }
        )

        assert first_response.status_code == 200

        # Second request should also be accepted.
        second_response = client.post(
            "/scan",
            headers=AUTH_HEADERS,
            json={
                "target": "127.0.0.1",
                "start_port": 1,
                "end_port": 10
            }
        )

        assert second_response.status_code == 200

        # Third request should be rejected because the
        # client has exceeded the temporary test limit.
        third_response = client.post(
            "/scan",
            headers=AUTH_HEADERS,
            json={
                "target": "127.0.0.1",
                "start_port": 1,
                "end_port": 10
            }
        )

        assert third_response.status_code == 429
        assert third_response.json() == {
            "detail": (
                "Rate limit exceeded. "
                "Please wait before submitting another scan."
            )
        }