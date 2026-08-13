# STRIDE Threat Model — PyWAF

This document presents the **STRIDE Threat Model** for PyWAF (Python Web Application Firewall).

---

## System Boundaries & Trust Assumptions

```text
               +----------------------------------+
               |        Untrusted Client          |
               +----------------------------------+
                                |
                                | HTTP Request
                                v
               +----------------------------------+
               |        PyWAF Middleware          |
               |  - X-Forwarded-For IP Extraction |
               |  - Double URL Decoding           |
               |  - Rule Inspection Engine        |
               |  - IP Rate Limiter               |
               +----------------------------------+
                     /                      \
      Allowed Call  /                        \ Blocked Call
                   v                          v
      +------------------------+    +-------------------+
      | Backend WSGI/ASGI App  |    | 403 Forbidden     |
      +------------------------+    | JSON Error + Ref  |
                                    +-------------------+
                                              |
                                              v
                                    +-------------------+
                                    | SQLite Log DB     |
                                    +-------------------+
```

---

## STRIDE Threat Categories & Mitigations

### 1. Spoofing Identity
* **Threat**: Attacker spoofing client IP via `X-Forwarded-For` header to bypass rate limits or whitelist rules.
* **Mitigation**: PyWAF extracts the first client IP in `X-Forwarded-For` chain and validates remote address against whitelist exact/prefix match rules (`waf/middleware.py`).

### 2. Tampering with Data
* **Threat**: Attacker using double-URL-encoding, unicode obfuscation, or payload splitting to bypass WAF pattern detection.
* **Mitigation**: PyWAF performs automatic double-URL-decoding and unicode normalization before rule regex evaluation (`waf/engine.py`).

### 3. Repudiation
* **Threat**: Malicious client denying access attempts or administrative actions.
* **Mitigation**: Every blocked request generates a unique reference code (`ref_code`) logged into a WAL-mode SQLite event database with timestamps, client IP, route, and rule triggers (`waf/logger.py`).

### 4. Information Disclosure
* **Threat**: WAF leaking backend stack trace, internal DB path, or rule pattern details in blocked responses.
* **Mitigation**: Blocked responses return sanitized JSON with `403 Forbidden`, status error message, and unique event reference code without stack traces (`dashboard/templates/block.html`).

### 5. Denial of Service (DoS)
* **Threat**: Resource exhaustion attacks via payload overload or high-frequency requests.
* **Mitigation**: Sliding window IP rate limiter (`waf/rate_limiter.py`) and automatic payload truncation for oversized requests.

### 6. Elevation of Privilege
* **Threat**: Command injection or SQL injection bypassing WAF to execute unauthorized commands on server.
* **Mitigation**: Expanded Command Injection ruleset (`CI_11` through `CI_15`) blocking shell operators, subcommands, and pipeline separators (`waf/rules.py`).
