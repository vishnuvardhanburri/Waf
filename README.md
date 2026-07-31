# 🛡️ PyWAF

[![Tests](https://github.com/vishnuvardhanburri/Waf/actions/workflows/tests.yml/badge.svg)](https://github.com/vishnuvardhanburri/Waf/actions/workflows/tests.yml)
![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/flask-%3E%3D2.3.0-lightgrey.svg)
![License MIT](https://img.shields.io/badge/license-MIT-green.svg)

PyWAF is a plug-and-play Web Application Firewall middleware for Flask applications. It provides real-time detection and blocking of common web vulnerabilities including SQL Injection, Cross-Site Scripting (XSS), Path Traversal, and Command Injection, along with a real-time monitoring dashboard.

## ✨ Features

- [x] **Zero-Config Integration**: Protect any Flask app with a single line of code.
- [x] **Real-time Threat Detection**: Blocks SQLi, XSS, Path Traversal, Command Injection, LDAP Injection, Header Injection, Bad Bots, and known security scanners.
- [x] **Rate Limiting**: Built-in sliding-window IP-based rate limiting to prevent abuse.
- [x] **Real-time Dashboard**: Monitor attacks via Server-Sent Events (SSE).
- [x] **Customizable Rules**: Add your own regular expressions or logic to detect specific threats.
- [x] **Monitor & Block Modes**: Test your rules safely before enforcing them.
- [x] **Proxy-aware IP Extraction**: Correctly extracts the real client IP from `X-Forwarded-For` even when behind multiple proxies.
- [x] **Double-URL-Decoded Detection**: Catches obfuscation via `%252e%252e%252f`-style payloads that bypass most naive WAFs.
- [x] **Listener Hooks**: Subscribe to events programmatically without monkey-patching the logger.

## 🚀 Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/vishnuvardhanburri/Waf.git
   cd Waf
   ```

2. **Run the startup script (installs dependencies & runs demo)**
   ```bash
   chmod +x run.sh
   ./run.sh
   ```

3. **View the Dashboard**
   Navigate to `http://127.0.0.1:8080/waf/dashboard` for live monitoring.

## 💻 Usage

Integrating PyWAF into your existing Flask application is extremely simple:

```python
from flask import Flask
from waf import PyWAF

app = Flask(__name__)

# Protect your app with one line
PyWAF.protect(app, config_path='config.yaml')

@app.route('/')
def index():
    return "Protected by PyWAF!"
```

### Listening to events (new)

You can subscribe to security events without monkey-patching the logger:

```python
waf = PyWAF.protect(app, config_path='config.yaml')

def my_handler(event):
    print(f"Saw {event['threat_type']} from {event['client_ip']}")

waf.logger.add_listener(my_handler)
# ...
waf.logger.remove_listener(my_handler)
```

Listeners are invoked **outside** the DB write lock, so a slow handler won't stall attack logging under load.

## ⚙️ Configuration Reference

The WAF behavior is customized via `config.yaml`:

| Key | Description | Default |
|-----|-------------|---------|
| `waf.mode` | `block` to block attacks, `monitor` to only log them, `off` to disable. | `block` |
| `waf.sensitivity` | Rule sensitivity (`strict`, `standard`, `permissive`). | `standard` |
| `waf.rate_limit.enabled` | Enable or disable rate limiting. | `true` |
| `waf.rate_limit.max_requests` | Max requests per IP in the window. | `100` |
| `waf.whitelist.paths` | Paths that bypass WAF. Trailing `/` = prefix match, no `/` = exact match. | `['/health', '/metrics', '/favicon.ico', '/waf/']` |
| `waf.logging.level` | Logging verbosity (`INFO`, `DEBUG`, `WARNING`). | `INFO` |
| `waf.logging.database` | SQLite database path (auto-aliased to `db_file`). | `logs/waf_events.db` |

## 📡 API Endpoints

The WAF dashboard exposes several API endpoints (under the path defined in config, default `/waf/`):

- `GET /waf/dashboard` — Dashboard UI.
- `GET /waf/api/stats` — Attack statistics.
- `GET /waf/api/events` — Retrieves recent WAF events (`limit`, `offset`, `threat_type`, `ip`).
- `GET /waf/api/events/stream` — SSE endpoint for live event streaming.
- `POST /waf/api/events/clear` — Clear all logged events.
- `GET /waf/api/rules` — View active WAF rules.

## 🧪 Testing

Run the comprehensive test suite with `pytest`:

```bash
pytest tests/
```

This runs 100+ tests including detection engine unit tests, Flask middleware integration tests, and parameterized OWASP attack payload tests.

## ⚔️ Attack Simulation

Test the WAF by sending malicious payloads to the demo app:

**SQL Injection:**
```bash
curl "http://127.0.0.1:8080/search?q=1%20OR%201=1"
```

**Cross-Site Scripting (XSS):**
```bash
curl "http://127.0.0.1:8080/search?q=<script>alert(1)</script>"
```

**Path Traversal:**
```bash
curl "http://127.0.0.1:8080/search?q=../../etc/passwd"
```

**Double-URL-Encoded Path Traversal (new):**
```bash
curl "http://127.0.0.1:8080/search?q=%252e%252e%252fetc%252fpasswd"
```

**Interpreter one-liners (new):**
```bash
curl "http://127.0.0.1:8080/search?q=python%20-c%20%22import%20os%22"
```

You should receive a `403 Forbidden` and see the attack logged in the dashboard.

## 📊 Dashboard

The dashboard shows:
- Total requests, blocked count, block rate
- Top blocked IPs
- Threat-type distribution
- Real-time event stream via SSE

## 🛡️ Defense Coverage (67+ rules)

| Category | Rules | Severity Range |
|----------|-------|----------------|
| SQL Injection | 15 (tautologies, comments, time-based, hex, stacked, metadata, …) | medium → critical |
| XSS | 15 (script tag, event handlers, JS protocols, encoding tricks, DOM) | low → critical |
| Path Traversal | 10 (Linux/Windows, URL-encoded, null byte, sensitive files) | high → critical |
| Command Injection | 15 (backticks, `$()`, shell commands, interpreters, output redirection) | high → critical |
| LDAP Injection | 5 (filter manipulation, wildcard, OR/AND) | high |
| Header Injection | 5 (CRLF, cookie injection, encoded variants) | medium → high |
| Bad Bots | 2 (script UAs, known scrapers) | low → high |
| Security Scanners | 2 (sqlmap, nikto, burp, …) | critical |

Rule sensitivity filtering:
- `permissive` — `critical` only
- `standard`   — `critical` + `high`
- `strict`     — `critical` + `high` + `medium`
- `paranoid`   — all severities

## 🏗️ Architecture

```text
       Incoming HTTP Request
               │
               ▼
      ┌─────────────────┐
      │ Flask App Entry │
      └────────┬────────┘
               │
      ┌────────▼────────┐
      │ PyWAF Middleware│ ◄── Rate Limiting, IP Blacklist, Whitelist, Proxy-aware IP
      └────────┬────────┘
               │
      ┌────────▼────────┐
      │  WAF Engine     │ ◄── Double URL-decoded input; SQLi, XSS, PT, CI, …
      └────────┬────────┘
               │
           Threat Detected?
           /            \
         YES             NO
         /                \
 ┌──────▼──────┐    ┌─────▼──────┐
 │ Log & Block │    │ Process Req│
 └──────┬──────┘    └─────┬──────┘
        │                 │
 ┌──────▼──────┐    ┌─────▼──────┐
 │ SSE UI +    │    │ HTTP 200 OK│
 │ Listeners   │    └────────────┘
 └─────────────┘
```

### Storage

- **SQLite** (`logs/waf_events.db`) — durable event log, WAL-mode journal for concurrent reads/writes.
- **JSON log file** (`logs/waf_events.log`) — one JSON event per line.
- **Console** — color-coded summary line per event.

The DB connection is **cached** (not opened/closed per request) and uses WAL mode + `synchronous=NORMAL` for high write throughput.

### Security Headers

Every response gets:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `X-WAF-Protected: PyWAF`
- `Content-Security-Policy` (default, only added if app didn't set one)

## 🆕 What's New

See [CHANGELOG.md](CHANGELOG.md) for the full history. Recent highlights:

- **Proxy-aware client IP** — first IP in `X-Forwarded-For`, not the whole header
- **Double-URL-decoded detection** — `%252e%252e%252f` no longer bypasses
- **Config `database` key** — admin overrides now actually take effect (aliased to `db_file`)
- **Listener hooks** — proper `add_listener()` API instead of monkey-patching
- **Persistent DB connection** — WAL mode, ~5-10× faster writes
- **Safer whitelist** — exact match unless you opt in to prefix with trailing `/`
- **Debug mode off by default** — opt in via `PYWAF_DEBUG=true` env var
- **5 new command-injection rules** — interpreters (`python -c`, `perl -e`), in-process exec calls, output redirection
- **Bytes-safe JSON body inspection**

## 📄 License

This project is licensed under the MIT License — see the LICENSE file for details.
