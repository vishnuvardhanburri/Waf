import time
import threading
from collections import defaultdict

class RateLimiter:
    """Simple sliding window rate limiter."""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)
        self.lock = threading.Lock()
        
    def is_allowed(self, client_ip: str) -> bool:
        """Checks if the client IP is allowed to make a request."""
        now = time.time()
        with self.lock:
            # Clean up old requests for this IP
            self.requests[client_ip] = [
                req_time for req_time in self.requests[client_ip]
                if now - req_time < self.window_seconds
            ]
            
            if len(self.requests[client_ip]) < self.max_requests:
                self.requests[client_ip].append(now)
                return True
            return False
            
    def get_remaining(self, client_ip: str) -> int:
        """Returns the number of remaining requests for the client IP."""
        now = time.time()
        with self.lock:
            valid_requests = sum(
                1 for req_time in self.requests[client_ip] 
                if now - req_time < self.window_seconds
            )
            return max(0, self.max_requests - valid_requests)
            
    def reset(self, client_ip: str = None):
        """Resets the counter for a specific IP or all IPs."""
        with self.lock:
            if client_ip:
                if client_ip in self.requests:
                    del self.requests[client_ip]
            else:
                self.requests.clear()
                
    def cleanup(self):
        """Removes expired entries from the dictionary."""
        now = time.time()
        with self.lock:
            empty_ips = []
            for ip, reqs in self.requests.items():
                self.requests[ip] = [
                    t for t in reqs if now - t < self.window_seconds
                ]
                if not self.requests[ip]:
                    empty_ips.append(ip)
                    
            for ip in empty_ips:
                del self.requests[ip]
