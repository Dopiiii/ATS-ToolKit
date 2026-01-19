"""Configuration management with .env support.

Loads configuration from environment variables with type validation.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

from src.core.error_handler import ConfigurationError


@dataclass
class AtsConfig:
    """Main configuration for ATS-Toolkit."""

    # Environment
    env: str = "production"
    log_level: str = "INFO"
    debug: bool = False

    # Performance
    threads: int = 50
    timeout: int = 60

    # API Keys
    api_shodan: Optional[str] = None
    api_hunter: Optional[str] = None
    api_virustotal: Optional[str] = None
    api_hibp: Optional[str] = None

    # Proxy
    proxy_enabled: bool = False
    proxy_host: Optional[str] = None
    proxy_port: Optional[int] = None

    # Server
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    streamlit_port: int = 8501

    # Paths
    project_root: Path = field(default_factory=lambda: Path.cwd())
    logs_dir: Path = field(default_factory=lambda: Path.cwd() / "logs")
    config_dir: Path = field(default_factory=lambda: Path.cwd() / "config")
    data_dir: Path = field(default_factory=lambda: Path.cwd() / "data")

    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        # Validate log level
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.log_level.upper() not in valid_levels:
            raise ConfigurationError(
                f"Invalid log level: {self.log_level}",
                config_key="log_level",
                remediation=f"Use one of: {', '.join(valid_levels)}",
            )

        # Validate threads
        if self.threads < 1 or self.threads > 1000:
            raise ConfigurationError(
                f"Invalid thread count: {self.threads}",
                config_key="threads",
                remediation="Use a value between 1 and 1000",
            )

        # Validate timeout
        if self.timeout < 1 or self.timeout > 300:
            raise ConfigurationError(
                f"Invalid timeout: {self.timeout}",
                config_key="timeout",
                remediation="Use a value between 1 and 300 seconds",
            )

        # Create directories if they don't exist
        for dir_path in [self.logs_dir, self.config_dir, self.data_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)

    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a service."""
        key_map = {
            "shodan": self.api_shodan,
            "hunter": self.api_hunter,
            "virustotal": self.api_virustotal,
            "hibp": self.api_hibp,
        }
        return key_map.get(service.lower())

    def has_api_key(self, service: str) -> bool:
        """Check if API key exists for a service."""
        key = self.get_api_key(service)
        return key is not None and len(key) > 0

    @property
    def proxy_url(self) -> Optional[str]:
        """Get proxy URL if enabled."""
        if not self.proxy_enabled or not self.proxy_host:
            return None

        if self.proxy_port:
            return f"http://{self.proxy_host}:{self.proxy_port}"
        return f"http://{self.proxy_host}"


@dataclass
class ConfigManager:
    """Manages application configuration."""

    config: AtsConfig
    env_file: Optional[Path] = None

    @classmethod
    def from_env(cls, env_file: Optional[Path] = None) -> "ConfigManager":
        """Load configuration from environment variables.

        Args:
            env_file: Path to .env file (default: .env in project root)

        Returns:
            ConfigManager instance with loaded configuration
        """
        # Determine project root
        if env_file:
            project_root = env_file.parent
        else:
            # Try to find project root by looking for pyproject.toml
            current = Path.cwd()
            while current != current.parent:
                if (current / "pyproject.toml").exists():
                    project_root = current
                    break
                current = current.parent
            else:
                project_root = Path.cwd()

            env_file = project_root / ".env"

        # Load .env file if it exists
        if env_file.exists():
            load_dotenv(env_file)

        # Helper to get env var with prefix
        def get_env(key: str, default: Optional[str] = None) -> Optional[str]:
            return os.getenv(f"ATS_{key}", default)

        def get_bool(key: str, default: bool = False) -> bool:
            value = get_env(key)
            if value is None:
                return default
            return value.lower() in ("true", "1", "yes", "on")

        def get_int(key: str, default: int) -> int:
            value = get_env(key)
            if value is None:
                return default
            try:
                return int(value)
            except ValueError:
                raise ConfigurationError(
                    f"Invalid integer value for {key}: {value}",
                    config_key=key,
                )

        # Build configuration
        config = AtsConfig(
            # Environment
            env=get_env("ENV", "production"),
            log_level=get_env("LOG_LEVEL", "INFO").upper(),
            debug=get_bool("DEBUG", False),
            # Performance
            threads=get_int("THREADS", 50),
            timeout=get_int("TIMEOUT", 60),
            # API Keys
            api_shodan=get_env("API_SHODAN"),
            api_hunter=get_env("API_HUNTER"),
            api_virustotal=get_env("API_VIRUSTOTAL"),
            api_hibp=get_env("API_HIBP"),
            # Proxy
            proxy_enabled=get_bool("PROXY_ENABLED", False),
            proxy_host=get_env("PROXY_HOST"),
            proxy_port=get_int("PROXY_PORT", 8080) if get_env("PROXY_PORT") else None,
            # Server
            api_host=get_env("API_HOST", "127.0.0.1"),
            api_port=get_int("API_PORT", 8000),
            streamlit_port=get_int("STREAMLIT_PORT", 8501),
            # Paths
            project_root=project_root,
            logs_dir=project_root / "logs",
            config_dir=project_root / "config",
            data_dir=project_root / "data",
        )

        return cls(config=config, env_file=env_file)

    def reload(self) -> None:
        """Reload configuration from environment."""
        if self.env_file and self.env_file.exists():
            load_dotenv(self.env_file, override=True)

        # Recreate config
        manager = ConfigManager.from_env(self.env_file)
        self.config = manager.config


# Global configuration instance
_config_manager: Optional[ConfigManager] = None


def init_config(env_file: Optional[Path] = None) -> ConfigManager:
    """Initialize global configuration.

    Args:
        env_file: Path to .env file (optional)

    Returns:
        ConfigManager instance
    """
    global _config_manager

    if _config_manager is None:
        _config_manager = ConfigManager.from_env(env_file)

    return _config_manager


def get_config() -> AtsConfig:
    """Get global configuration.

    Returns:
        AtsConfig instance

    Raises:
        ConfigurationError: If configuration not initialized
    """
    if _config_manager is None:
        raise ConfigurationError(
            "Configuration not initialized",
            remediation="Call init_config() first",
        )

    return _config_manager.config


def reload_config() -> None:
    """Reload global configuration from environment."""
    if _config_manager is None:
        raise ConfigurationError(
            "Configuration not initialized",
            remediation="Call init_config() first",
        )

    _config_manager.reload()
