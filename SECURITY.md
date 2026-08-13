# Security Policy

## Acquisition-Grade Security Posture

PyWAF is an enterprise-grade Python Web Application Firewall (WAF) designed to inspect, detect, and block malicious traffic (SQLi, XSS, Path Traversal, Command Injection, LDAP Injection) in real-time with zero external runtime dependencies.

This document outlines PyWAF's security architecture, supported versions, secret handling, and vulnerability reporting procedures in compliance with **OpenSSF Gold Level Standards**.

---

## Supported Versions

We provide active security updates for the current major release branch:

| Version | Supported | Security SLA |
| --- | --- | --- |
| `v1.x` (latest main) | Yes | 24h Acknowledgment / 30-day Fix |
| `< 1.0.0` | No | Upgrade to `v1.x` required |

---

## Security Controls & Defense-in-Depth

| Module | Defense Mechanism | Implementation File |
| --- | --- | --- |
| **IP Extraction** | Proxy-aware `X-Forwarded-For` first-IP extraction | `waf/middleware.py` |
| **Payload Normalization** | Double-URL-decoding & unicode normalization | `waf/engine.py` |
| **SQLi Protection** | Regex rule engine with 15+ SQL injection signatures | `waf/rules.py` |
| **XSS Protection** | Script tag, event handler & javascript URI detection | `waf/rules.py` |
| **Path Traversal** | Directory traversal & encoded sequence detector | `waf/rules.py` |
| **Command Injection** | Shell operator & subcommand injection rules (CI_1 to CI_15) | `waf/rules.py` |
| **Rate Limiting** | Sliding window IP rate limiter with configurable bucket size | `waf/rate_limiter.py` |
| **Security Headers** | `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy` | `waf/middleware.py` |
| **Audit Logging** | WAL-mode SQLite event logger with connection caching | `waf/logger.py` |

---

## Vulnerability Disclosure & Reporting Process

PyWAF follows **Coordinated Vulnerability Disclosure (CVD)** principles.

### Reporting a Vulnerability

If you discover a security vulnerability or rule bypass in PyWAF, **do NOT open a public GitHub issue**. Report it privately to our Security Team:

* 📧 **Security Contact**: `security@pywaf.org`
* 🔑 **PGP Key Fingerprint**: `F5A2 889C 1042 B791 3E0B  99A4 C821 7041 99F2 E10B`

### Response SLAs

1. **Initial Acknowledgment**: Within **24 hours** of report receipt.
2. **Triaging & Severity Rating**: Within **7 days**, using CVSS v3.1 scoring.
3. **Patch & Security Release**: Target within **30 days** (or sooner for Critical/High severity issues).
4. **Public Advisory**: Published via GitHub Security Advisories after patch deployment.

---

## Safe Harbor Statement

Security researchers acting in good faith to discover and report vulnerabilities in accordance with this policy will not be subject to legal action by the project maintainers.
