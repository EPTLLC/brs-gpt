# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-08 19:19:25 UTC
# Status: Modified
# Telegram: https://t.me/easyprotech

"""
Configuration Manager

Handles OpenAI API key storage and retrieval with secure file permissions.
Implements zero-configuration philosophy with sensible defaults.
"""

import os
import json
import stat
from pathlib import Path
from typing import Optional, Dict, Any
from dotenv import load_dotenv


class ConfigManager:
    """Manages BRS-GPT configuration with secure API key storage."""
    
    def __init__(self):
        """Initialize configuration manager with default paths."""
        override_dir = os.getenv("BRS_GPT_CONFIG_DIR")
        if override_dir:
            self.config_dir = Path(override_dir)
        else:
            self.config_dir = Path.home() / ".config" / "brs-gpt"
        self.config_file = self.config_dir / "config.json"

        # Load .env file by default for API keys and configuration
        env_file = Path.cwd() / ".env"
        if env_file.exists():
            load_dotenv(env_file)

        self._ensure_config_dir()
    
    def _ensure_config_dir(self) -> None:
        """Create configuration directory with secure permissions."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        # Set directory permissions to 700 (owner only)
        try:
            os.chmod(self.config_dir, stat.S_IRWXU)
        except Exception:
            # Best-effort on non-POSIX filesystems
            pass
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file."""
        if not self.config_file.exists():
            return {}
        
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    
    def _save_config(self, config: Dict[str, Any]) -> bool:
        """Save configuration to file with secure permissions."""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
            
            # Set file permissions to 600 (owner read/write only)
            os.chmod(self.config_file, stat.S_IRUSR | stat.S_IWUSR)
            return True
            
        except IOError:
            return False
    
    def save_api_key(self, api_key: str) -> bool:
        """Save OpenAI API key securely."""
        if not api_key or not api_key.startswith('sk-'):
            return False
        
        config = self._load_config()
        config['openai_api_key'] = api_key
        config['configured'] = True
        
        return self._save_config(config)
    
    def get_api_key(self) -> Optional[str]:
        """Retrieve OpenAI API key from environment or config file."""
        # First check environment variable
        api_key = os.getenv('OPENAI_API_KEY')
        if api_key and api_key.startswith('sk-'):
            return api_key

        # Fallback to config file
        config = self._load_config()
        if not config.get('configured'):
            return None
        return config.get('openai_api_key')

    def has_api_key(self) -> bool:
        """Check if API key is configured in environment or config file."""
        api_key = self.get_api_key()
        return api_key is not None and api_key.startswith('sk-')
    
    def get_default_settings(self) -> Dict[str, Any]:
        """Get default analysis settings."""
        # Read models from .env if available (optional)
        env_model = os.getenv('OPENAI_MODEL') or 'gpt-5-mini'
        env_search_model = os.getenv('OPENAI_SEARCH_MODEL') or 'gpt-4o-mini-search-preview'
        env_fallback_model = os.getenv('OPENAI_FALLBACK_MODEL') or 'gpt-5-nano'

        defaults: Dict[str, Any] = {
            'active_profile': 'balanced',
            'phases': {'ai': True, 'recon': True, 'xss': True},
            'recon': {
                'max_subdomains': 1000,
                'dns_timeout': 5,
                'port_scan_timeout': 30,
                'concurrent_requests': 32,
            },
            'xss': {
                'max_payloads': 500,
                'request_timeout': 15,
                'rate_limit': 8.0,
                'contexts': ['html', 'attribute', 'script', 'css', 'uri', 'svg'],
                'max_urls': 8,
                'max_forms_per_url': 5,
            },
            'ai': {
                'provider': 'openai',
                'model': env_model,                # analysis model (configurable)
                'search_model': env_search_model,  # search/OSINT model (configurable)
                'fallback_model': env_fallback_model,  # last-resort fallback
                'max_tokens': 4000,
                'temperature': 0.1,
            },
            'output': {
                'format': 'html',
                'include_raw_data': False,
                'show_false_positives': False,
            },
        }
        return defaults

    def get_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Return predefined scanning profiles."""
        return {
            'lightning': {
                'recon': {'max_subdomains': 50, 'concurrent_requests': 64, 'port_scan_timeout': 10},
                'xss': {'max_payloads': 100, 'rate_limit': 20.0, 'request_timeout': 8},
                'ai': {'max_tokens': 1500, 'temperature': 0.1},
            },
            'fast': {
                'recon': {'max_subdomains': 120, 'concurrent_requests': 32, 'port_scan_timeout': 15},
                'xss': {'max_payloads': 200, 'rate_limit': 12.0, 'request_timeout': 10},
                'ai': {'max_tokens': 2000, 'temperature': 0.1},
            },
            'balanced': {},
            'deep': {
                'recon': {'max_subdomains': 2000, 'concurrent_requests': 48, 'port_scan_timeout': 45},
                'xss': {'max_payloads': 800, 'rate_limit': 10.0, 'request_timeout': 20},
                'ai': {'max_tokens': 6000, 'temperature': 0.1},
            },
        }

    def apply_profile(self, profile_name: str) -> bool:
        """Apply predefined profile to current settings and mark active_profile."""
        profiles = self.get_profiles()
        if profile_name not in profiles:
            return False
        config = self._load_config()
        settings = config.get('settings', self.get_default_settings())

        # Merge profile deltas
        profile_delta = profiles[profile_name]
        for category, values in profile_delta.items():
            if category in settings:
                settings[category].update(values)
            else:
                settings[category] = values

        settings['active_profile'] = profile_name
        config['settings'] = settings
        return self._save_config(config)
    
    def update_settings(self, new_settings: Dict[str, Any]) -> bool:
        """Update analysis settings."""
        config = self._load_config()
        settings = config.get('settings', self.get_default_settings())
        
        # Deep merge settings
        for category, values in new_settings.items():
            if category in settings:
                settings[category].update(values)
            else:
                settings[category] = values
        
        config['settings'] = settings
        return self._save_config(config)
    
    def get_settings(self) -> Dict[str, Any]:
        """Get current analysis settings."""
        config = self._load_config()
        return config.get('settings', self.get_default_settings())
    
    def reset_config(self) -> bool:
        """Reset configuration to defaults."""
        if self.config_file.exists():
            try:
                self.config_file.unlink()
                return True
            except OSError:
                return False
        return True
