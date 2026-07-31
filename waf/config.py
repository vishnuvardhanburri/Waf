"""
PyWAF Configuration Loader

Loads configuration from YAML files, environment variables, or dictionaries.
Supports nested 'waf:' key in YAML and merges with defaults.
"""
import os
import yaml
from typing import Dict, Any, Optional, List


class WAFConfig:
    """Configuration loader for PyWAF."""

    def __init__(self, config_dict: Optional[Dict[str, Any]] = None):
        self._config = {
            'enabled': True,
            'mode': 'block',
            'sensitivity': 'standard',
            'rate_limit': {
                'enabled': True,
                'max_requests': 100,
                'window_seconds': 60
            },
            'whitelist': {
                'paths': ['/health', '/metrics', '/favicon.ico', '/waf/'],
                'ips': []
            },
            'blacklist': {
                'ips': []
            },
            'logging': {
                'enabled': True,
                'console': True,
                'log_file': 'logs/waf_events.log',
                'db_file': 'logs/waf_events.db',
                'level': 'INFO',
                'max_events': 10000
            },
            'dashboard': {
                'enabled': True,
                'path': '/waf/dashboard'
            },
            'custom_rules': []
        }

        if config_dict:
            # Support nested 'waf:' key in YAML
            if 'waf' in config_dict:
                config_dict = config_dict['waf']
            # Alias: 'database' (used in config.yaml) maps to 'db_file' (used by logger)
            logging_cfg = config_dict.get('logging', {})
            if isinstance(logging_cfg, dict) and 'database' in logging_cfg:
                logging_cfg.setdefault('db_file', logging_cfg.pop('database'))
                if not logging_cfg.get('db_file'):
                    logging_cfg['db_file'] = logging_cfg.pop('database')
                config_dict['logging'] = logging_cfg
            self._merge(self._config, config_dict)

        self._load_from_env()

    def _merge(self, base: Dict[str, Any], override: Dict[str, Any]):
        """Deep merge override dict into base dict."""
        for k, v in override.items():
            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                self._merge(base[k], v)
            else:
                base[k] = v

    def _load_from_env(self):
        """Loads configuration from environment variables with PYWAF_ prefix."""
        if 'PYWAF_ENABLED' in os.environ:
            self._config['enabled'] = os.environ['PYWAF_ENABLED'].lower() == 'true'
        if 'PYWAF_MODE' in os.environ:
            self._config['mode'] = os.environ['PYWAF_MODE']
        if 'PYWAF_SENSITIVITY' in os.environ:
            self._config['sensitivity'] = os.environ['PYWAF_SENSITIVITY']

    @classmethod
    def load(cls, path: Optional[str] = None):
        """Loads config from YAML file if provided."""
        config_dict = {}
        if path and os.path.exists(path):
            with open(path, 'r') as f:
                loaded = yaml.safe_load(f)
                if loaded:
                    config_dict = loaded
        return cls(config_dict)

    @property
    def enabled(self) -> bool:
        return self._config.get('enabled', True)

    @property
    def mode(self) -> str:
        return self._config.get('mode', 'block')

    @property
    def sensitivity(self) -> str:
        return self._config.get('sensitivity', 'standard')

    @property
    def rate_limit(self) -> dict:
        return self._config.get('rate_limit', {})

    @property
    def whitelist_paths(self) -> List[str]:
        """Returns whitelisted URL path prefixes."""
        wl = self._config.get('whitelist', {})
        if isinstance(wl, dict):
            return wl.get('paths', [])
        return []

    @property
    def whitelist_ips(self) -> List[str]:
        """Returns whitelisted IP addresses."""
        wl = self._config.get('whitelist', {})
        if isinstance(wl, dict):
            return wl.get('ips', [])
        return []

    @property
    def blacklist_ips(self) -> List[str]:
        """Returns blacklisted IP addresses."""
        bl = self._config.get('blacklist', {})
        if isinstance(bl, dict):
            return bl.get('ips', [])
        return []

    @property
    def logging(self) -> dict:
        return self._config.get('logging', {})

    @property
    def dashboard(self) -> dict:
        return self._config.get('dashboard', {})

    @property
    def custom_rules(self) -> list:
        return self._config.get('custom_rules', [])
