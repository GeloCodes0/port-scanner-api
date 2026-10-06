import socket
from concurrent.futures import ThreadPoolExecutor


def identify_service(port):
    """
    Identify the common service associated with a TCP port.

    Python uses the operating system's service-name database
    to map well-known port numbers to service names.
    """

    try:
        return socket.getservbyport(port, "tcp")

    except OSError:
        # Some ports do not have a registered service name.
        return "unknown"


def scan_port(target, port, timeout=1.0):
    """
    Check whether a single TCP port is accepting connections.

    Args:
        target: IP address or hostname to scan.
        port: TCP port number to check.
        timeout: Maximum time to wait for the connection.

    Returns:
        True when the port is open.
        False when the connection fails or times out.
    """

    # Create an IPv4 TCP socket.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Prevent the scanner from waiting indefinitely.
    sock.settimeout(timeout)

    try:
        # connect_ex() returns 0 when the connection succeeds.
        result = sock.connect_ex((target, port))

        return result == 0

    except socket.error:
        # Treat socket errors as a closed/unreachable port.
        return False

    finally:
        # Always close the socket after scanning.
        sock.close()


def scan_ports(
    target,
    start_port,
    end_port,
    timeout=1.0,
    max_workers=100,
):
    """
    Scan a range of TCP ports concurrently.

    Args:
        target: IP address or hostname to scan.
        start_port: First TCP port in the scan range.
        end_port: Last TCP port in the scan range.
        timeout: Maximum time to wait for each connection.
        max_workers: Maximum number of concurrent scan tasks.

    Returns:
        A list of dictionaries containing each open port
        and its identified service.
    """

    open_ports = []

    # Create a controlled pool of worker threads.
    #
    # max_workers determines how many ports can be scanned
    # concurrently. A higher value can improve performance,
    # but also increases resource and network usage.
    with ThreadPoolExecutor(max_workers=max_workers) as executor:

        # Submit one scan task for every port.
        futures = {
            executor.submit(
                scan_port,
                target,
                port,
                timeout,
            ): port
            for port in range(start_port, end_port + 1)
        }

        # Collect results as each scan finishes.
        for future in futures:
            port = futures[future]

            try:
                # Only add ports that accepted the connection.
                if future.result():
                    open_ports.append(
                        {
                            "port": port,
                            "service": identify_service(port),
                        }
                    )

            except Exception:
                # Ignore an individual failed scan rather than
                # stopping the entire scanning operation.
                continue

    # Return results in numerical port order.
    return sorted(
        open_ports,
        key=lambda item: item["port"]
    )