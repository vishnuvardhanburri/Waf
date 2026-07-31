"""
PyWAF Logger

Structured JSON logging with SQLite persistence, file output, and color-coded console.
Thread-safe for concurrent Flask request handling.
"""
import sqlite3
import json
import logging
import threading
import os
from datetime import datetime


class WAFLogger:
    """Handles logging of WAF security events to SQLite, file, and console."""

    def __init__(self, config: dict):
        self.config = config
        self.db_path = config.get('db_file', 'logs/waf_events.db')
        self.log_file = config.get('log_file', 'logs/waf_events.log')
        self.console_enabled = config.get('console', True)
        self.lock = threading.RLock()
        # Hooks invoked after each event is persisted (e.g. for SSE broadcasting).
        self._callbacks = []  # list[callable(event_dict)] - thread-safe registration

        # Ensure log directories exist
        for path in [self.db_path, self.log_file]:
            directory = os.path.dirname(path)
            if directory:
                os.makedirs(directory, exist_ok=True)

        self._db_conn = None
        self._init_db()
        self._init_file_logger()

    def _get_conn(self):
        """Return a cached SQLite connection (safe for use with check_same_thread=False)."""
        if self._db_conn is None:
            self._db_conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                isolation_level=None,  # autocommit; we manage transactions explicitly
            )
            self._db_conn.execute('PRAGMA journal_mode=WAL')
            self._db_conn.execute('PRAGMA synchronous=NORMAL')
            self._db_conn.execute('PRAGMA temp_store=MEMORY')
        return self._db_conn

    def _init_db(self):
        """Initialize SQLite database with events table and indexes."""
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE,
                    timestamp TEXT,
                    client_ip TEXT,
                    method TEXT,
                    path TEXT,
                    threat_type TEXT,
                    pattern_matched TEXT,
                    source TEXT,
                    payload TEXT,
                    action TEXT,
                    request_id TEXT,
                    user_agent TEXT,
                    response_code INTEGER
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip ON events(client_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_type ON events(threat_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_time ON events(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_action ON events(action)')
            conn.commit()

    def _init_file_logger(self):
        """Initialize file-based JSON logger."""
        self.logger = logging.getLogger('PyWAF')
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            fh = logging.FileHandler(self.log_file)
            fh.setFormatter(logging.Formatter('%(message)s'))
            self.logger.addHandler(fh)

    def log_event(self, event: dict):
        """Logs a security event to database, file, and console."""
        if not self.config.get('enabled', True):
            return

        event['timestamp'] = event.get('timestamp', datetime.utcnow().isoformat() + 'Z')

        # JSON file log
        try:
            self.logger.info(json.dumps(event, default=str))
        except Exception:
            pass

        # Console output with color coding
        if self.console_enabled:
            action = event.get('action', 'unknown')
            color = '\033[91m' if action == 'block' else ('\033[93m' if action == 'rate_limit' else '\033[92m')
            reset = '\033[0m'
            threat = event.get('threat_type', 'CLEAN')
            ip = event.get('client_ip', 'unknown')
            path = event.get('path', '/')
            print(f"{color}[PyWAF] {action.upper()} | {threat} | IP: {ip} | Path: {path}{reset}")

        # SQLite insert using cached connection
        with self.lock:
            try:
                conn = self._get_conn()
                conn.execute('''
                    INSERT OR IGNORE INTO events (
                        event_id, timestamp, client_ip, method, path,
                        threat_type, pattern_matched, source, payload,
                        action, request_id, user_agent, response_code
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event.get('event_id'), event.get('timestamp'), event.get('client_ip'),
                    event.get('method'), event.get('path'), event.get('threat_type'),
                    event.get('pattern_matched'), event.get('source'), event.get('payload'),
                    event.get('action'), event.get('request_id'), event.get('user_agent'),
                    event.get('response_code')
                ))
                conn.commit()
            except Exception as e:
                print(f"\033[91m[PyWAF] DB Error: {e}\033[0m")

        # Fan out to external subscribers (e.g. SSE broadcasters)
        # Outside the DB lock so a slow callback doesn't stall the writer.
        callbacks = list(self._callbacks)
        for cb in callbacks:
            try:
                cb(event)
            except Exception:
                pass

    def get_events(self, limit=100, offset=0, filters=None) -> list:
        """Query events from SQLite with optional filters."""
        filters = filters or {}
        query = "SELECT * FROM events WHERE 1=1"
        params = []

        if 'client_ip' in filters:
            query += " AND client_ip = ?"
            params.append(filters['client_ip'])

        if 'threat_type' in filters:
            query += " AND threat_type = ?"
            params.append(filters['threat_type'])

        if 'action' in filters:
            query += " AND action = ?"
            params.append(filters['action'])

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self.lock:
            conn = self._get_conn()
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()

        return [dict(row) for row in rows]

    def get_stats(self) -> dict:
        """Returns aggregated statistics for the dashboard."""
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM events")
            total = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM events WHERE action = 'block'")
            blocked = cursor.fetchone()[0]

            cursor.execute(
                "SELECT threat_type, COUNT(*) as count FROM events "
                "WHERE threat_type IS NOT NULL GROUP BY threat_type ORDER BY count DESC"
            )
            by_type = {row[0]: row[1] for row in cursor.fetchall()}

            cursor.execute(
                "SELECT client_ip, COUNT(*) as count FROM events "
                "WHERE action = 'block' GROUP BY client_ip ORDER BY count DESC LIMIT 10"
            )
            top_ips = {row[0]: row[1] for row in cursor.fetchall()}

        return {
            'total_requests': total,
            'blocked_requests': blocked,
            'block_rate': round((blocked / total * 100), 1) if total > 0 else 0,
            'by_threat_type': by_type,
            'top_blocked_ips': top_ips
        }

    def clear_events(self):
        """Clears all events from the database."""
        with self.lock:
            conn = self._get_conn()
            conn.execute("DELETE FROM events")
            conn.commit()

    def add_listener(self, callback):
        """Register a callable that receives each event dict after it is persisted."""
        with self.lock:
            if callback not in self._callbacks:
                self._callbacks.append(callback)

    def remove_listener(self, callback):
        """Unregister a previously added listener."""
        with self.lock:
            if callback in self._callbacks:
                self._callbacks.remove(callback)

    def close(self):
        """Close the cached DB connection (call on app shutdown)."""
        with self.lock:
            if self._db_conn is not None:
                try:
                    self._db_conn.close()
                except Exception:
                    pass
                self._db_conn = None
