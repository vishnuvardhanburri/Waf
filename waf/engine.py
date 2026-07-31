import json
from collections import namedtuple
from typing import Optional, Any, Dict, List
import urllib.parse

ThreatInfo = namedtuple('ThreatInfo', ['threat_type', 'pattern_matched', 'description', 'severity', 'source', 'payload'])

class WAFEngine:
    def __init__(self, rules: Dict[str, List[Dict[str, Any]]], sensitivity: str = 'standard'):
        self.rules = rules
        self.sensitivity = sensitivity

    def inspect(self, data: str, source: str = 'unknown') -> Optional[ThreatInfo]:
        """Scans a string against all rules."""
        if not data or not isinstance(data, str):
            return None

        # Decode up to two levels to catch double-encoded payloads like %252e%252e%252f
        # (becomes %2e%2e%2f after first decode, then ../ after second).
        decoded_data = urllib.parse.unquote_plus(data)
        if '%' in decoded_data:
            decoded_data = urllib.parse.unquote_plus(decoded_data)

        for threat_category, category_rules in self.rules.items():
            for rule in category_rules:
                match = rule['pattern'].search(decoded_data)
                if match:
                    return ThreatInfo(
                        threat_type=threat_category,
                        pattern_matched=match.group(0),
                        description=rule['description'],
                        severity=rule['severity'],
                        source=source,
                        payload=data[:200]
                    )
        return None

    def inspect_deep(self, obj: Any, source_prefix: str) -> Optional[ThreatInfo]:
        """Recursively inspects nested dicts/lists."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                threat = self.inspect(str(k), f"{source_prefix}.key:{k}")
                if threat: return threat
                threat = self.inspect_deep(v, f"{source_prefix}.{k}")
                if threat: return threat
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                threat = self.inspect_deep(v, f"{source_prefix}[{i}]")
                if threat: return threat
        elif isinstance(obj, (str, bytes)):
            # bytes is decoded as latin-1 to preserve byte values safely
            value = obj.decode('latin-1', errors='replace') if isinstance(obj, bytes) else obj
            return self.inspect(value, source_prefix)
        else:
            return self.inspect(str(obj), source_prefix)
        return None

    def inspect_request(self, flask_request) -> Optional[ThreatInfo]:
        """Inspects a full Flask request."""
        # Check URL path
        threat = self.inspect(flask_request.path, 'url_path')
        if threat: return threat
        
        # Check Query parameters
        for k, v in flask_request.args.items():
            threat = self.inspect(k, 'query_param_key')
            if threat: return threat
            threat = self.inspect(v, f"query_param_value:{k}")
            if threat: return threat
            
        # Check Headers
        headers_to_check = ['User-Agent', 'Referer', 'Cookie', 'X-Forwarded-For']
        for h in headers_to_check:
            val = flask_request.headers.get(h)
            if val:
                threat = self.inspect(val, f"header:{h}")
                if threat: return threat
                
        # Check JSON body
        if flask_request.is_json:
            try:
                json_data = flask_request.get_json(silent=True)
                if json_data:
                    threat = self.inspect_deep(json_data, 'json_body')
                    if threat: return threat
            except Exception:
                pass
                
        # Check Form data
        if flask_request.form:
            for k, v in flask_request.form.items():
                threat = self.inspect(k, 'form_key')
                if threat: return threat
                threat = self.inspect(v, f"form_value:{k}")
                if threat: return threat
                
        return None
