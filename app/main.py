import logging
import os
import secrets
import socket
import time
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from app.scanner import scan_ports


# Load environment variables from the local .env file.
load_dotenv()


# Create the directory used for local audit logs.
#
# The directory is created automatically when the API starts,
# so the application does not require manual setup.
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)


# Configure a dedicated audit logger.
#
# Audit events are written to logs/scanner.log rather than
# being mixed with the application's normal console output.
audit_logger = logging.getLogger("port_scanner_audit")
audit_logger.setLevel(logging.INFO)

# Prevent duplicate log entries if this module is reloaded.
if not audit_logger.handlers:
    file_handler = logging.FileHandler(
        LOG_DIR / "scanner.log",
        encoding="utf-8"
    )

    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s"
        )
    )

    audit_logger.addHandler(file_handler)


app = FastAPI(
    title="Port Scanner API",
    description="A REST API for scanning TCP ports on authorised targets.",
    version="1.0.0",
)


# Stores recent scan timestamps for each client IP address.
#
# Example:
# {
#     "127.0.0.1": [timestamp1, timestamp2, timestamp3]
# }
#
# This provides a lightweight in-memory rate limiter.
rate_limit_state = {}


def get_authorized_targets():
    """
    Read the authorised scanning targets from the
    AUTHORIZED_TARGETS environment variable.

    Targets are stored as a comma-separated list, for example:

        AUTHORIZED_TARGETS=127.0.0.1,localhost
    """

    configured_targets = os.getenv("AUTHORIZED_TARGETS", "")

    # Split the comma-separated value into individual targets.
    targets = {
        target.strip().lower()
        for target in configured_targets.split(",")
        if target.strip()
    }

    return targets


def get_api_key():
    """
    Read the API key from the environment.

    The API key is stored outside the source code so that
    authentication credentials are not hardcoded into the application.
    """

    api_key = os.getenv("API_KEY", "")

    if not api_key:
        raise ValueError("API_KEY is not configured.")

    return api_key


def get_scan_timeout():
    """
    Read the scan timeout from the environment.

    Returns:
        The timeout in seconds as a floating-point number.

    Raises:
        ValueError: If the configured value is not a valid
        positive number.
    """

    timeout = float(os.getenv("SCAN_TIMEOUT", "1.0"))

    if timeout <= 0:
        raise ValueError("SCAN_TIMEOUT must be greater than 0.")

    return timeout


def get_max_workers():
    """
    Read the maximum number of concurrent scan workers
    from the environment.

    Returns:
        The maximum number of worker threads.

    Raises:
        ValueError: If the configured value is not a
        positive integer.
    """

    max_workers = int(os.getenv("MAX_WORKERS", "100"))

    if max_workers <= 0:
        raise ValueError("MAX_WORKERS must be greater than 0.")

    return max_workers


def get_max_scan_ports():
    """
    Read the maximum number of ports that may be included
    in a single scan request.

    Returns:
        The maximum permitted scan range size.

    Raises:
        ValueError: If the configured value is not a
        positive integer.
    """

    max_scan_ports = int(os.getenv("MAX_SCAN_PORTS", "5000"))

    if max_scan_ports <= 0:
        raise ValueError("MAX_SCAN_PORTS must be greater than 0.")

    return max_scan_ports


def get_rate_limit_requests():
    """
    Read the maximum number of scan requests allowed
    during the configured rate-limit window.

    Returns:
        Maximum number of requests allowed.

    Raises:
        ValueError: If the configured value is not a
        positive integer.
    """

    rate_limit_requests = int(
        os.getenv("RATE_LIMIT_REQUESTS", "10")
    )

    if rate_limit_requests <= 0:
        raise ValueError(
            "RATE_LIMIT_REQUESTS must be greater than 0."
        )

    return rate_limit_requests


def get_rate_limit_window():
    """
    Read the rate-limit time window from the environment.

    Returns:
        The rate-limit window in seconds.

    Raises:
        ValueError: If the configured value is not a
        positive number.
    """

    rate_limit_window = float(
        os.getenv("RATE_LIMIT_WINDOW", "60")
    )

    if rate_limit_window <= 0:
        raise ValueError(
            "RATE_LIMIT_WINDOW must be greater than 0."
        )

    return rate_limit_window


def is_rate_limited(client_ip):
    """
    Determine whether a client has exceeded the configured
    scan request limit.

    A sliding time window is used. Requests older than the
    configured window are removed before checking the limit.

    Args:
        client_ip: IP address of the client making the request.

    Returns:
        True if the client has exceeded the rate limit.
        False otherwise.
    """

    # Load the rate-limit configuration.
    max_requests = get_rate_limit_requests()
    window = get_rate_limit_window()

    current_time = time.monotonic()

    # Get the client's previous request timestamps.
    timestamps = rate_limit_state.get(client_ip, [])

    # Keep only requests that occurred within the current window.
    recent_timestamps = [
        timestamp
        for timestamp in timestamps
        if current_time - timestamp < window
    ]

    # If the client has already reached the limit, reject the request.
    if len(recent_timestamps) >= max_requests:
        rate_limit_state[client_ip] = recent_timestamps

        return True

    # Record the current request.
    recent_timestamps.append(current_time)

    rate_limit_state[client_ip] = recent_timestamps

    return False


def log_audit_event(event, client_ip, details=""):
    """
    Write a security-relevant event to the audit log.

    API keys and other authentication credentials are deliberately
    excluded from the logged information.
    """

    message = f"event={event} | client={client_ip}"

    if details:
        message += f" | {details}"

    audit_logger.info(message)


class ScanRequest(BaseModel):
    """
    Request model defining the target and port range
    supplied to the scanner.
    """

    target: str = Field(..., min_length=1)
    start_port: int = Field(..., ge=1, le=65535)
    end_port: int = Field(..., ge=1, le=65535)


@app.get("/")
def root():
    """
    Provide a simple health-check endpoint.
    """

    return {
        "message": "Port Scanner API is running"
    }


@app.post("/scan")
def scan(
    request: ScanRequest,
    http_request: Request,
    x_api_key: str | None = Header(default=None),
):
    """
    Scan the requested TCP port range on an authorised target.

    The endpoint requires a valid API key supplied through
    the X-API-Key HTTP header.

    Authorised scan requests are also rate-limited based
    on the client's IP address.

    Security-relevant events are recorded in the audit log.
    """

    # Identify the client making the request.
    #
    # FastAPI's Request object provides the remote client's
    # IP address through the client connection information.
    client_ip = (
        http_request.client.host
        if http_request.client
        else "unknown"
    )

    # Load the expected API key from the environment.
    try:
        expected_api_key = get_api_key()

    except ValueError as error:
        log_audit_event(
            "CONFIGURATION_ERROR",
            client_ip,
            "API key configuration is invalid"
        )

        raise HTTPException(
            status_code=500,
            detail=f"Invalid API configuration: {error}",
        )

    # Reject requests that do not provide the API key
    # or provide an incorrect key.
    #
    # compare_digest() performs a timing-resistant comparison
    # rather than a normal string comparison.
    if not secrets.compare_digest(
        x_api_key or "",
        expected_api_key
    ):
        log_audit_event(
            "AUTH_FAILURE",
            client_ip,
            "Invalid or missing API key"
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key.",
        )

    # Load the currently configured authorised targets.
    authorized_targets = get_authorized_targets()

    # Check whether the requested target is authorised.
    if request.target.lower() not in authorized_targets:
        log_audit_event(
            "TARGET_REJECTED",
            client_ip,
            f"target={request.target}"
        )

        raise HTTPException(
            status_code=403,
            detail="Target is not authorised for scanning.",
        )

    # Make sure the requested port range is valid.
    if request.start_port > request.end_port:
        log_audit_event(
            "INVALID_PORT_RANGE",
            client_ip,
            (
                f"target={request.target} | "
                f"ports={request.start_port}-{request.end_port}"
            )
        )

        raise HTTPException(
            status_code=400,
            detail="start_port must be less than or equal to end_port.",
        )

    # Calculate how many ports the request is asking to scan.
    requested_port_count = (
        request.end_port - request.start_port + 1
    )

    # Load the maximum permitted scan range from the environment.
    try:
        max_scan_ports = get_max_scan_ports()

    except ValueError as error:
        log_audit_event(
            "CONFIGURATION_ERROR",
            client_ip,
            "Maximum scan range configuration is invalid"
        )

        raise HTTPException(
            status_code=500,
            detail=f"Invalid scanner configuration: {error}",
        )

    # Reject excessively large scan requests before the scanner
    # creates any concurrent scan tasks.
    if requested_port_count > max_scan_ports:
        log_audit_event(
            "SCAN_RANGE_REJECTED",
            client_ip,
            (
                f"target={request.target} | "
                f"ports={request.start_port}-{request.end_port} | "
                f"requested={requested_port_count} | "
                f"maximum={max_scan_ports}"
            )
        )

        raise HTTPException(
            status_code=400,
            detail=(
                f"Scan range cannot exceed {max_scan_ports} ports."
            ),
        )

    # Apply rate limiting before performing DNS resolution
    # or starting the actual port scan.
    try:
        if is_rate_limited(client_ip):
            log_audit_event(
                "RATE_LIMIT_EXCEEDED",
                client_ip,
                f"target={request.target}"
            )

            raise HTTPException(
                status_code=429,
                detail=(
                    "Rate limit exceeded. "
                    "Please wait before submitting another scan."
                ),
            )

    except ValueError as error:
        log_audit_event(
            "CONFIGURATION_ERROR",
            client_ip,
            "Rate-limit configuration is invalid"
        )

        raise HTTPException(
            status_code=500,
            detail=f"Invalid rate-limit configuration: {error}",
        )

    # Resolve the hostname before scanning.
    try:
        resolved_ip = socket.gethostbyname(request.target)

    except socket.gaierror:
        log_audit_event(
            "DNS_RESOLUTION_FAILURE",
            client_ip,
            f"target={request.target}"
        )

        raise HTTPException(
            status_code=400,
            detail="Target hostname could not be resolved.",
        )

    # Load scanner configuration from the environment.
    try:
        scan_timeout = get_scan_timeout()
        max_workers = get_max_workers()

    except ValueError as error:
        log_audit_event(
            "CONFIGURATION_ERROR",
            client_ip,
            "Scanner configuration is invalid"
        )

        raise HTTPException(
            status_code=500,
            detail=f"Invalid scanner configuration: {error}",
        )

    # Record the start time immediately before the scan begins.
    start_time = time.perf_counter()

    # Run the concurrent TCP port scan using the configured
    # timeout and maximum number of workers.
    open_ports = scan_ports(
        resolved_ip,
        request.start_port,
        request.end_port,
        timeout=scan_timeout,
        max_workers=max_workers,
    )

    # Calculate the total time taken by the scan.
    scan_time = time.perf_counter() - start_time

    # Record a successful scan in the audit log.
    log_audit_event(
        "SCAN_SUCCESS",
        client_ip,
        (
            f"target={request.target} | "
            f"resolved_ip={resolved_ip} | "
            f"ports={request.start_port}-{request.end_port} | "
            f"open_ports={len(open_ports)} | "
            f"duration={scan_time:.4f}s"
        )
    )

    return {
        "target": request.target,
        "resolved_ip": resolved_ip,
        "scanned_ports": requested_port_count,
        "open_ports": open_ports,
        "scan_time_seconds": round(scan_time, 4),
    }