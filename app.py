"""
PyWAF Demo Application

A self-contained Flask application demonstrating PyWAF in action.
Includes WAF middleware, real-time dashboard, and sample API routes.
"""
import os
import sys
import json
import queue
import threading
from flask import Flask, render_template, request, jsonify, Response

# Ensure the project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from waf import PyWAF
from waf.rules import SECURITY_RULES

# ---------------------------------------------------------------------------
# Flask Application Setup
# ---------------------------------------------------------------------------
app = Flask(
    __name__,
    template_folder='dashboard/templates',
    static_folder='dashboard/static'
)

# ---------------------------------------------------------------------------
# SSE (Server-Sent Events) Implementation
# ---------------------------------------------------------------------------
event_subscribers = []
subscribers_lock = threading.Lock()


def broadcast_event(event):
    """Push an event to all connected SSE clients."""
    with subscribers_lock:
        dead = []
        for q in event_subscribers:
            try:
                q.put_nowait(event)
            except queue.Full:
                dead.append(q)
        for q in dead:
            event_subscribers.remove(q)


# ---------------------------------------------------------------------------
# Initialize PyWAF
# ---------------------------------------------------------------------------
config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.yaml')
waf_instance = PyWAF.protect(app, config_path=config_path)

# Broadcast events to SSE clients via a proper listener hook (no monkey-patching).
waf_instance.logger.add_listener(broadcast_event)


# ---------------------------------------------------------------------------
# Dashboard Routes (under /waf/ prefix)
# ---------------------------------------------------------------------------
@app.route('/waf/dashboard')
def waf_dashboard():
    """Serve the real-time WAF monitoring dashboard."""
    return render_template('dashboard.html')


@app.route('/waf/api/stats')
def waf_api_stats():
    """Return aggregated WAF statistics as JSON."""
    stats = waf_instance.logger.get_stats()
    # Count active rules
    rule_count = sum(len(rules) for rules in waf_instance.engine.rules.values())
    stats['active_rules'] = rule_count
    stats['status'] = 'active' if waf_instance.config.enabled else 'disabled'
    stats['mode'] = waf_instance.config.mode
    return jsonify(stats)


@app.route('/waf/api/events')
def waf_api_events():
    """Return WAF events with optional filtering."""
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    filters = {}

    threat_type = request.args.get('threat_type')
    if threat_type:
        filters['threat_type'] = threat_type

    ip = request.args.get('ip')
    if ip:
        filters['client_ip'] = ip

    events = waf_instance.logger.get_events(limit=limit, offset=offset, filters=filters)
    return jsonify(events)


@app.route('/waf/api/events/stream')
def waf_api_events_stream():
    """SSE endpoint for real-time event streaming."""
    def event_stream():
        q = queue.Queue(maxsize=200)
        with subscribers_lock:
            event_subscribers.append(q)
        try:
            while True:
                event = q.get(timeout=30)
                yield f"data: {json.dumps(event, default=str)}\n\n"
        except queue.Empty:
            # Send keepalive comment
            yield ": keepalive\n\n"
        except GeneratorExit:
            pass
        finally:
            with subscribers_lock:
                if q in event_subscribers:
                    event_subscribers.remove(q)

    return Response(
        event_stream(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )


@app.route('/waf/api/events/clear', methods=['POST'])
def waf_api_events_clear():
    """Clear all stored WAF events."""
    waf_instance.logger.clear_events()
    return jsonify({'status': 'success', 'message': 'All events cleared'})


@app.route('/waf/api/rules')
def waf_api_rules():
    """Return the list of active WAF rules."""
    rules_summary = {}
    for category, rule_list in SECURITY_RULES.items():
        rules_summary[category] = [
            {
                'id': r['id'],
                'description': r['description'],
                'severity': r['severity'],
                'enabled': r['enabled']
            }
            for r in rule_list
        ]
    return jsonify(rules_summary)


# ---------------------------------------------------------------------------
# Demo Application Routes
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    """Welcome endpoint."""
    return jsonify({
        'app': 'PyWAF Demo Application',
        'version': '1.0.0',
        'status': 'running',
        'message': 'Welcome to the PyWAF demo! Try sending some attacks to test the WAF.',
        'dashboard': '/waf/dashboard',
        'endpoints': {
            'search': '/search?q=<query>',
            'login': 'POST /login',
            'users': '/api/users',
            'data': 'POST /api/data',
            'health': '/health'
        }
    })


@app.route('/search', methods=['GET', 'POST'])
def search():
    """Search endpoint — test with query params or JSON body."""
    query = request.args.get('q') or ''
    if request.is_json:
        query = request.json.get('q', query)
    return jsonify({'results': f'Search results for: {query}'})


@app.route('/login', methods=['POST'])
def login():
    """Demo login endpoint."""
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')
    if username == 'admin' and password == 'admin':
        return jsonify({'status': 'success', 'token': 'demo-jwt-token-xyz'})
    return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401


@app.route('/api/users')
def users():
    """Sample user data endpoint."""
    return jsonify([
        {'id': 1, 'name': 'Alice', 'role': 'admin'},
        {'id': 2, 'name': 'Bob', 'role': 'user'},
        {'id': 3, 'name': 'Charlie', 'role': 'user'}
    ])


@app.route('/api/data', methods=['POST'])
def data_echo():
    """Echo endpoint — returns whatever JSON you send."""
    data = request.get_json() or {}
    return jsonify({'received': data})


@app.route('/health')
def health():
    """Health check endpoint (whitelisted by WAF)."""
    return jsonify({'status': 'healthy', 'waf': 'active'})


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
def print_banner():
    """Print the PyWAF ASCII art banner."""
    banner = """
\033[96m
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║   ██████╗ ██╗   ██╗██╗    ██╗ █████╗ ███████╗            ║
    ║   ██╔══██╗╚██╗ ██╔╝██║    ██║██╔══██╗██╔════╝            ║
    ║   ██████╔╝ ╚████╔╝ ██║ █╗ ██║███████║█████╗              ║
    ║   ██╔═══╝   ╚██╔╝  ██║███╗██║██╔══██║██╔══╝              ║
    ║   ██║        ██║   ╚███╔███╔╝██║  ██║██║                 ║
    ║   ╚═╝        ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝                 ║
    ║                                                          ║
    ║   🛡️  Plug-and-Play Web Application Firewall for Flask   ║
    ╚══════════════════════════════════════════════════════════╝
\033[0m"""
    print(banner)
    print(f"\033[92m  [✓] WAF Mode      : {waf_instance.config.mode.upper()}\033[0m")
    print(f"\033[92m  [✓] Sensitivity   : {waf_instance.config.sensitivity}\033[0m")
    print(f"\033[92m  [✓] Rate Limit    : {waf_instance.config.rate_limit.get('max_requests', 100)} req/min\033[0m")
    rule_count = sum(len(rules) for rules in waf_instance.engine.rules.values())
    print(f"\033[92m  [✓] Active Rules  : {rule_count}\033[0m")
    print(f"\033[92m  [✓] Dashboard     : http://127.0.0.1:8080/waf/dashboard\033[0m")
    print(f"\033[93m  [!] Server        : http://127.0.0.1:8080\033[0m")
    print()


if __name__ == '__main__':
    print_banner()
    # Disable Werkzeug debugger (RCE risk if exposed). Enable explicitly via PYWAF_DEBUG=true.
    debug_mode = os.environ.get('PYWAF_DEBUG', '').lower() == 'true'
    app.run(host='0.0.0.0', port=8080, debug=debug_mode)
