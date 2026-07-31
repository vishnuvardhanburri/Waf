# Changelog

All notable changes to PyWAF are documented here.

## [Unreleased] — Hardening & Performance

### Security
- **Proxy-aware client IP extraction**: `WAFMiddleware._get_real_client_ip()` now parses the first IP from `X-Forwarded-For` instead of trusting the entire header (which is trivially spoofable).
- **Double-URL-decoded payloads**: `WAFEngine.inspect()` now performs a second `unquote_plus` pass when `%` is still present, catching `%252e%252e%252f`-style bypasses.
- **Config key aliasing**: `config.yaml` `logging.database` is now correctly mapped to the logger's `db_file`, so admin-supplied DB paths actually apply.
- **Hardened whitelist semantics**: trailing `/` means prefix match, otherwise exact match. `/waf/` no longer accidentally matches `/waf-admin/foo`.
- **Debug mode off by default**: `app.py` no longer starts Werkzeug's debugger (RCE risk); opt-in via `PYWAF_DEBUG=true`.
- **Expanded command-injection ruleset**: added CI_11–CI_15 covering interpreter one-liners (`python -c`, `perl -e`, `node -e`, …), in-process execution calls (`eval`, `system`, `popen`, `subprocess.Popen`), and output redirection (`> file`, `>> file`).
- **Bytes-safe body inspection**: `WAFEngine.inspect_deep()` decodes bytes safely via latin-1 with `errors='replace'`.

### Performance
- **Cached SQLite connection**: `WAFLogger` keeps a single `sqlite3` connection with WAL journal mode and `synchronous=NORMAL`, replacing the previous per-call `connect()`/`close()` pattern. Big win under load.
- **Listener isolation**: log-event listeners fire outside the DB lock, so a slow subscriber can't stall attack-event writes.

### Code Quality
- **Replaced monkey-patch with listener API**: `WAFLogger.add_listener(cb)` / `remove_listener(cb)`. The SSE broadcaster in `app.py` now uses this instead of hot-patching `log_event`.
- **Header application** now uses `setdefault` so the WAF doesn't overwrite app-set `X-Content-Type-Options` etc.; CSP is added only when the app didn't provide one.
- **`.gitignore`** added (`venv/`, `__pycache__/`, `logs/*.db`, etc.).

## [1.0.0] — Initial Release

- Core WAF middleware with rule-based detection
- 67 detection rules across 8 categories
- Sliding-window rate limiter
- SQLite + JSON-file + console logging
- Real-time dashboard with SSE
- `config.yaml`-driven configuration
