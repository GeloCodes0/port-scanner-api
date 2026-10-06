from unittest.mock import patch

from app.scanner import identify_service, scan_port, scan_ports


def test_identify_service_returns_known_service():
    """
    Verify that a well-known TCP port is mapped to
    the expected service.
    """

    assert identify_service(80) == "http"


def test_identify_service_returns_unknown_for_unregistered_port():
    """
    Verify that an unregistered port returns 'unknown'.
    """

    with patch(
        "app.scanner.socket.getservbyport",
        side_effect=OSError
    ):
        assert identify_service(12345) == "unknown"


def test_scan_port_returns_true_when_port_is_open():
    """
    Verify that scan_port() returns True when the TCP
    connection succeeds.
    """

    with patch("app.scanner.socket.socket") as mock_socket:
        mock_socket.return_value.connect_ex.return_value = 0

        assert scan_port("127.0.0.1", 80) is True


def test_scan_port_returns_false_when_port_is_closed():
    """
    Verify that scan_port() returns False when the TCP
    connection fails.
    """

    with patch("app.scanner.socket.socket") as mock_socket:
        mock_socket.return_value.connect_ex.return_value = 1

        assert scan_port("127.0.0.1", 80) is False


def test_scan_ports_returns_open_ports_with_services():
    """
    Verify that scan_ports() returns open ports together
    with their identified services.
    """

    with patch(
        "app.scanner.scan_port",
        side_effect=[False, True, False, True]
    ):
        with patch(
            "app.scanner.identify_service",
            side_effect=["http", "https"]
        ):
            result = scan_ports(
                target="127.0.0.1",
                start_port=80,
                end_port=83
            )

    assert result == [
        {
            "port": 81,
            "service": "http"
        },
        {
            "port": 83,
            "service": "https"
        }
    ]