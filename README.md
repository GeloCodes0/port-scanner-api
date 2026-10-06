# Port Scanner API

A Python-based REST API for performing concurrent TCP port scans against authorised targets.

This project demonstrates how a network security tool can be exposed through a REST API while applying authentication, authorisation, rate limiting, input validation, resource controls, and audit logging.

The API accepts a target and port range, validates the request, checks that the target is authorised, and then performs concurrent TCP connection attempts to identify open ports and common services.

> **Security note:** This project is designed for authorised security testing and educational use. Only scan systems you own or have explicit permission to test.

---

## What This Project Demonstrates

- TCP networking with Python sockets
- Concurrent network operations using `ThreadPoolExecutor`
- REST API development with FastAPI
- API-key authentication
- Timing-resistant credential comparison
- Target allowlisting
- Input validation
- Rate limiting
- Resource limits
- Security audit logging
- Hostname resolution
- Automated testing

---

## How It Works

A request to the scanning endpoint follows a series of security and validation checks before any network scanning takes place:

```text
Client
  │
  ▼
POST /scan
  │
  ├── Validate request
  ├── Authenticate API key
  ├── Check target allowlist
  ├── Validate port range
  ├── Apply scan limits
  ├── Apply rate limiting
  └── Resolve target
          │
          ▼
   Concurrent TCP Scanner
          │
          ├── Test ports
          ├── Identify open ports
          └── Identify services
          │
          ▼
      Audit Logging
          │
          ▼
      API Response
```

Each port is tested using a TCP connection. `ThreadPoolExecutor` allows multiple ports to be checked concurrently rather than scanning each port sequentially.

---

## Security

Security was considered at both the API and scanning layers.

### API Authentication

The `/scan` endpoint requires an API key through the `X-API-Key` header.

The key is stored in environment variables rather than hardcoded into the application, and `secrets.compare_digest()` is used for timing-resistant comparison.

### Target Allowlisting

The API does not allow arbitrary targets to be scanned.

Permitted targets are configured through an environment variable:

```env
AUTHORIZED_TARGETS=127.0.0.1,localhost
```

This provides an application-level restriction against unauthorised scanning.

### Rate Limiting

Requests are rate-limited by client IP address to reduce excessive scanning requests and resource consumption.

```env
RATE_LIMIT_REQUESTS=10
RATE_LIMIT_WINDOW=60
```

### Resource Protection

A maximum number of ports can be scanned in a single request:

```env
MAX_SCAN_PORTS=5000
```

This prevents a single request from creating an unnecessarily large number of concurrent scanning tasks.

### Audit Logging

Security-relevant events are recorded in `logs/scanner.log`, including:

- Successful scans
- Authentication failures
- Unauthorised targets
- Invalid port ranges
- Excessive scan ranges
- Rate-limit violations
- DNS resolution failures

Sensitive credentials are not written to the logs.

---

## Project Structure

```text
07-port-scanner-api/
├── app/
│   ├── __init__.py
│   ├── scanner.py
│   └── main.py
├── tests/
│   ├── __init__.py
│   ├── test_scanner.py
│   └── test_api.py
├── logs/
│   └── scanner.log
├── .env
├── .env.example
├── .gitignore
└── requirements.txt
```

### Key Components

**`scanner.py`**  
Contains the core TCP scanning logic, concurrent scanning, and service identification.

**`main.py`**  
Provides the FastAPI application and handles authentication, authorisation, validation, rate limiting, logging, and scan requests.

**`tests/`**  
Contains automated tests for the scanner and API behaviour.

---

## Configuration

Create a `.env` file in the project root:

```env
AUTHORIZED_TARGETS=127.0.0.1,localhost
SCAN_TIMEOUT=1.0
MAX_WORKERS=100
API_KEY=your-api-key-here
MAX_SCAN_PORTS=5000
RATE_LIMIT_REQUESTS=10
RATE_LIMIT_WINDOW=60
```

| Variable | Description |
| --- | --- |
| `AUTHORIZED_TARGETS` | Targets permitted for scanning |
| `SCAN_TIMEOUT` | TCP connection timeout in seconds |
| `MAX_WORKERS` | Maximum concurrent scanning workers |
| `API_KEY` | API authentication key |
| `MAX_SCAN_PORTS` | Maximum ports allowed per request |
| `RATE_LIMIT_REQUESTS` | Maximum requests per rate-limit window |
| `RATE_LIMIT_WINDOW` | Rate-limit window in seconds |

The `.env` file is excluded from version control.

---

## Installation

Create a virtual environment and install the dependencies:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

---

## Running the API

Start the development server:

```powershell
python -m uvicorn app.main:app --reload
```

The API will be available at:

`http://127.0.0.1:8000`

Interactive API documentation is available through Swagger:

`http://127.0.0.1:8000/docs`

---

## Example

### Request

`POST /scan`

Header:

```text
X-API-Key: your-api-key
```

Request body:

```json
{
  "target": "127.0.0.1",
  "start_port": 1,
  "end_port": 500
}
```

### Response

```json
{
  "target": "127.0.0.1",
  "resolved_ip": "127.0.0.1",
  "scanned_ports": 500,
  "open_ports": [
    {
      "port": 135,
      "service": "epmap"
    },
    {
      "port": 445,
      "service": "microsoft-ds"
    }
  ],
  "scan_time_seconds": 5.1159
}
```

---

## Performance

The scanner uses concurrent workers to improve performance when checking multiple ports.

During development, a 500-port localhost scan improved from approximately **10.15 seconds** using the earlier configuration to **5.12 seconds** after introducing concurrent scanning.

Actual performance will vary depending on timeout settings, firewall behaviour, network conditions, and system resources.

---

## Testing

Automated tests are provided using **pytest** and cover the scanner, API behaviour, authentication, authorisation, validation, rate limiting, and error handling.

Run the test suite with:

```powershell
pytest
```

---

## Technologies

- **Python** — Core implementation
- **FastAPI** — REST API framework
- **Uvicorn** — Development server
- **Pydantic** — Request validation
- **Python Sockets** — TCP network communication
- **ThreadPoolExecutor** — Concurrent scanning
- **python-dotenv** — Environment configuration
- **pytest** — Automated testing

---

## Limitations

This is a lightweight portfolio implementation rather than a production vulnerability scanner.

Current limitations include:

- TCP scanning only
- IPv4 scanning only
- Basic service identification
- No UDP scanning
- No banner grabbing
- In-memory rate limiting
- Local audit logging

---

## Future Improvements

Potential improvements include:

- Role-based access control
- Persistent scan history
- Background scan jobs
- UDP and IPv6 support
- Advanced service detection
- JSON/CSV result export
- Docker deployment
- Web dashboard
- Centralised security monitoring

---

## Author

**GeloCodes**

Cybersecurity / Security and Network Engineering portfolio project focused on practical Python networking, REST API development, concurrency, and application security.