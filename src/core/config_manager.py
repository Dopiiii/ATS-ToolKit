"""Configuration management for ATS-Toolkit.

Loads configuration from .env files and provides typed access
to settings via the AtsConfig dataclass.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv


@dataclass
class AtsConfig:
    """Core configuration for ATS-Toolkit."""

    api_keys: dict[str, str] = field(default_factory=dict)
    log_level: str = "INFO"
    log_format: str = "console"
    data_dir: str = "data"
    max_concurrent: int = 5
    timeout: int = 30

    def has_api_key(self, service: str) -> bool:
        """Check if an API key exists for a service.

        Args:
            service: Service name (e.g., 'shodan', 'virustotal')

        Returns:
            True if the key exists and is non-empty
        """
        return bool(self.api_keys.get(service))

    def get_api_key(self, service: str) -> Optional[str]:
        """Get the API key for a service.

        Args:
            service: Service name

        Returns:
            The API key string, or None if not set
        """
        return self.api_keys.get(service)


class ConfigManager:
    """Manages ATS-Toolkit configuration.

    Loads settings from a .env file and environment variables.
    API keys are detected by the ``_API_KEY`` suffix convention.
    """

    def __init__(self, env_path: Optional[str] = None) -> None:
        """Initialize the configuration manager.

        Args:
            env_path: Path to .env file. Defaults to project root .env.
        """
        if env_path is None:
            env_path = str(Path(__file__).resolve().parents[2] / ".env")

        self._env_path = env_path
        self._overrides: dict[str, Any] = {}

        # Load .env file into environment
        load_dotenv(self._env_path, override=False)

        self.config = self._build_config()

    def _build_config(self) -> AtsConfig:
        """Build an AtsConfig from environment variables."""
        api_keys: dict[str, str] = {}

        # Collect API keys: any env var ending with _API_KEY
        for key, value in os.environ.items():
            if key.endswith("_API_KEY") and value:
                service = key.replace("_API_KEY", "").lower()
                api_keys[service] = value

        return AtsConfig(
            api_keys=api_keys,
            log_level=os.getenv("ATS_LOG_LEVEL", "INFO").upper(),
            log_format=os.getenv("ATS_LOG_FORMAT", "console"),
            data_dir=os.getenv("ATS_DATA_DIR", "data"),
            max_concurrent=int(os.getenv("ATS_MAX_CONCURRENT", "5")),
            timeout=int(os.getenv("ATS_TIMEOUT", "30")),
        )

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value.

        Checks overrides first, then environment variables.

        Args:
            key: Configuration key
            default: Default value if key is not found

        Returns:
            The configuration value
        """
        if key in self._overrides:
            return self._overrides[key]
        return os.getenv(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a runtime configuration override.

        Args:
            key: Configuration key
            value: Value to set
        """
        self._overrides[key] = value
        os.environ[key] = str(value)

        # Rebuild config so AtsConfig reflects changes
        self.config = self._build_config()

    def reload(self) -> None:
        """Reload configuration from the .env file."""
        load_dotenv(self._env_path, override=True)
        self.config = self._build_config()


# Singleton instance
_config_manager: Optional[ConfigManager] = None


def get_config_manager(env_path: Optional[str] = None) -> ConfigManager:
    """Get the singleton ConfigManager instance.

    Args:
        env_path: Path to .env file (only used on first call)

    Returns:
        The shared ConfigManager instance
    """
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(env_path)
    return _config_manager
