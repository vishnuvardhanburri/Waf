"""
PyWAF Middleware Integration Tests

Tests the WAF middleware through Flask's test client — verifying
403 blocks, 200 pass-throughs, rate limiting, and security headers.
"""
import pytest
import json
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, jsonify, request
from waf import PyWAF


@pytest.fixture
def app(tmp_path):
    """Create a Flask test app with PyWAF attached."""
    # Write a test config with small rate limit for testing
    config_file = tmp_path / "test_config.yaml"
    config_file.write_text(f"""
waf:
  enabled: true
  mode: block
  sensitivity: standard
  rate_limit:
    enabled: true
    max_requests: 10
    window_seconds: 60
  whitelist:
    paths:
      - /health
      - /waf/
    ips: []
  blacklist:
    ips: []
  logging:
    enabled: true
    console: false
    log_file: "{tmp_path}/test_waf.log"
    db_file: "{tmp_path}/test_waf.db"
    level: INFO
  dashboard:
    enabled: false
""")

    test_app = Flask(__name__)

    @test_app.route('/')
    def index():
        return jsonify({"status": "ok"})

    @test_app.route('/health')
    def health():
        return jsonify({"status": "healthy"})

    @test_app.route('/search')
    def search():
        q = request.args.get('q', '')
        return jsonify({"results": f"Search: {q}"})

    @test_app.route('/api/data', methods=['POST'])
    def data():
        return jsonify(request.get_json())

    PyWAF.protect(test_app, config_path=str(config_file))
    return test_app


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


class TestCleanRequests:
    """Verify clean traffic passes through."""

    def test_root_returns_200(self, client):
        resp = client.get('/')
        assert resp.status_code == 200

    def test_search_clean_query(self, client):
        resp = client.get('/search?q=laptop')
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert 'laptop' in data['results']


class TestSQLInjectionBlocking:
    """Verify SQL injection is blocked."""

    def test_sqli_in_query_param(self, client):
        resp = client.get("/search?q=' OR 1=1 --")
        assert resp.status_code == 403
        data = json.loads(resp.data)
        assert data.get('threat_type') == 'SQL_INJECTION'

    def test_sqli_union_select(self, client):
        resp = client.get("/search?q=1 UNION SELECT * FROM users")
        assert resp.status_code == 403

    def test_sqli_in_post_body(self, client):
        resp = client.post('/api/data',
                           json={"username": "admin'; DROP TABLE users; --"},
                           content_type='application/json')
        assert resp.status_code == 403


class TestXSSBlocking:
    """Verify XSS attacks are blocked."""

    def test_xss_script_tag(self, client):
        resp = client.get("/search?q=<script>alert(1)</script>")
        assert resp.status_code == 403

    def test_xss_event_handler(self, client):
        resp = client.get("/search?q=<img onerror=alert(1) src=x>")
        assert resp.status_code == 403


class TestPathTraversalBlocking:
    """Verify path traversal is blocked."""

    def test_path_traversal(self, client):
        resp = client.get("/search?q=../../etc/passwd")
        assert resp.status_code == 403


class TestWhitelisting:
    """Verify whitelisted paths bypass WAF."""

    def test_health_bypasses_waf(self, client):
        # /health is whitelisted — even with attack payload, it should pass
        resp = client.get("/health?q=' OR 1=1")
        assert resp.status_code == 200


class TestRateLimiting:
    """Verify rate limiting returns 429."""

    def test_rate_limit_exceeded(self, client):
        # Config sets max_requests=10
        for _ in range(10):
            client.get('/')
        resp = client.get('/')
        assert resp.status_code == 429
        data = json.loads(resp.data)
        assert 'RATE_LIMIT' in data.get('threat_type', '')


class TestSecurityHeaders:
    """Verify security headers are added."""

    def test_has_security_headers(self, client):
        resp = client.get('/')
        assert resp.headers.get('X-Content-Type-Options') == 'nosniff'
        assert resp.headers.get('X-Frame-Options') == 'DENY'
        assert resp.headers.get('X-XSS-Protection') == '1; mode=block'
        assert resp.headers.get('X-WAF-Protected') == 'PyWAF'

    def test_has_csp_header(self, client):
        resp = client.get('/')
        assert 'Content-Security-Policy' in resp.headers


class TestResponseFormat:
    """Verify blocked response format."""

    def test_blocked_response_has_reference(self, client):
        resp = client.get("/search?q=' OR 1=1 --")
        assert resp.status_code == 403
        data = json.loads(resp.data)
        assert 'reference' in data
        assert 'threat_type' in data
        assert data['status'] == 'Blocked'
