"""
PyWAF Initialization Module

Exports the main PyWAF class for single-line integration with Flask applications.
Usage: PyWAF.protect(app, config_path='config.yaml')
"""
from typing import Optional


class PyWAF:
    """
    Main PyWAF class for integration with Flask applications.

    Usage:
        # Single-line integration
        waf = PyWAF.protect(app, config_path='config.yaml')

        # Factory pattern
        waf = PyWAF(config_path='config.yaml')
        waf.init_app(app)
    """

    def __init__(self, app=None, config_path: Optional[str] = None):
        from .engine import WAFEngine
        from .config import WAFConfig
        from .rate_limiter import RateLimiter
        from .logger import WAFLogger
        from .rules import get_rules

        self.config = WAFConfig.load(config_path)
        self.logger = WAFLogger(self.config.logging)
        self.rate_limiter = RateLimiter(
            max_requests=self.config.rate_limit.get('max_requests', 100),
            window_seconds=self.config.rate_limit.get('window_seconds', 60)
        )
        self.engine = WAFEngine(
            rules=get_rules(sensitivity=self.config.sensitivity),
            sensitivity=self.config.sensitivity
        )
        self.app = app

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Initialize the Flask application with WAF middleware."""
        from .middleware import WAFMiddleware

        if not self.config.enabled:
            return

        self.app = app
        self.middleware = WAFMiddleware(
            app=app,
            engine=self.engine,
            logger=self.logger,
            rate_limiter=self.rate_limiter,
            config=self.config
        )
        self.middleware.setup()

        # Store reference in app.extensions for dashboard access
        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['pywaf'] = self

    @classmethod
    def protect(cls, app, config_path: Optional[str] = None):
        """
        Shorthand method to protect a Flask application in one line.

        Returns the PyWAF instance for further configuration.
        """
        instance = cls(app=app, config_path=config_path)
        return instance
