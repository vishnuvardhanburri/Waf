"""
PyWAF Middleware

Flask before_request / after_request hooks that integrate the WAF transparently.
Handles path whitelisting, IP filtering, rate limiting, and threat inspection.
"""
from flask import request, jsonify
import uuid


class WAFMiddleware:
    """WAF middleware that hooks into Flask request lifecycle."""

    def __init__(self, app, engine, logger, rate_limiter, config):
        self.app = app
        self.engine = engine
        self.logger = logger
        self.rate_limiter = rate_limiter
        self.config = config

    def setup(self):
        """Registers Flask before_request and after_request hooks."""
        self.app.before_request(self.before_request_handler)
        self.app.after_request(self.after_request_handler)

    def before_request_handler(self):
        """Main WAF filter — runs before every incoming request."""
        request_id = str(uuid.uuid4())
        client_ip = self._get_real_client_ip()

        # 1. Check path whitelist — skip WAF for whitelisted paths.
        # Convention: trailing '/' = prefix match, no '/' = exact match.
        # Prevents accidental bypass where `/waf-` would match `/waf/`.
        for entry in self.config.whitelist_paths:
            if entry.endswith('/'):
                if request.path.startswith(entry):
                    return None
            else:
                if request.path == entry:
                    return None

        # 2. Check IP blacklist — block blacklisted IPs
        if client_ip in self.config.blacklist_ips:
            self._log_event(client_ip, request_id, 'BLACKLISTED_IP', None, 'ip_blacklist', None, 'block', 403)
            return self._render_block_response('Request blocked by Web Application Firewall (WAF)', 'BLACKLISTED_IP', request_id, client_ip, 403)

        # 3. Check IP whitelist — skip if whitelisted
        if client_ip in self.config.whitelist_ips:
            return None

        # 4. Check rate limit
        if self.config.rate_limit.get('enabled', True):
            if not self.rate_limiter.is_allowed(client_ip):
                self._log_event(client_ip, request_id, 'RATE_LIMIT_EXCEEDED', None, 'rate_limiter', None, 'rate_limit', 429)
                return self._render_block_response('Too Many Requests', 'RATE_LIMIT_EXCEEDED', request_id, client_ip, 429)

        # 5. Run engine inspection
        threat = self.engine.inspect_request(request)
        if threat:
            action = 'block' if self.config.mode == 'block' else 'monitor'
            self._log_event(
                client_ip, request_id, threat.threat_type,
                threat.pattern_matched, threat.source, threat.payload,
                action, 403 if action == 'block' else 200
            )

            if action == 'block':
                return self._render_block_response('Request blocked by Web Application Firewall (WAF)', threat.threat_type, request_id, client_ip, 403)

        return None

    def _render_block_response(self, error_msg, threat_type, request_id, client_ip, status_code):
        from flask import render_template, make_response
        
        # Check if the client prefers HTML (e.g., a browser)
        if request.accept_mimetypes.accept_html:
            try:
                html = render_template('block.html', 
                                     reference=request_id, 
                                     threat_type=threat_type, 
                                     client_ip=client_ip)
                return make_response(html, status_code)
            except Exception as e:
                # Fallback if template is missing
                print(f"[PyWAF] Warning: Could not render block.html: {e}")
                
        # API requests get JSON
        return jsonify({
            'status': 'Blocked',
            'error': error_msg,
            'threat_type': threat_type,
            'reference': request_id
        }), status_code

    def _log_event(self, ip, req_id, threat_type, pattern, source, payload, action, code):
        """Creates and logs a security event."""
        event = {
            'event_id': str(uuid.uuid4()),
            'client_ip': ip,
            'method': request.method,
            'path': request.path,
            'threat_type': threat_type,
            'pattern_matched': pattern,
            'source': source,
            'payload': payload,
            'action': action,
            'request_id': req_id,
            'user_agent': request.headers.get('User-Agent', ''),
            'response_code': code
        }
        self.logger.log_event(event)

    @staticmethod
    def _get_real_client_ip():
        """
        Extract the real client IP respecting proxy headers.

        Takes the FIRST IP from X-Forwarded-For (the original client) and
        falls back to remote_addr. Mitigates trivial spoofing where the
        entire header is attacker-controlled.
        """
        xff = request.headers.get('X-Forwarded-For')
        if xff:
            first = xff.split(',')[0].strip()
            if first:
                return first
        return request.remote_addr or '127.0.0.1'

    def after_request_handler(self, response):
        """Adds security headers to every response without clobbering existing ones."""
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('X-XSS-Protection', '1; mode=block')
        response.headers['X-WAF-Protected'] = 'PyWAF'
        # Only set a default CSP if the app didn't already provide one.
        # CSP allows CDN for dashboard charts and fonts.
        if 'Content-Security-Policy' not in response.headers:
            response.headers['Content-Security-Policy'] = (
                "default-src 'self'; "
                "script-src 'self' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "connect-src 'self'; "
                "img-src 'self' data:;"
            )
        return response
