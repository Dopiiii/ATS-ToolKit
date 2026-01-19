"""Unit tests for core components."""

import pytest
from pathlib import Path
import tempfile
import os

from src.core.error_handler import (
    AtsException,
    ModuleNotFoundError,
    APIKeyMissingError,
    ValidationError,
    ExecutionError,
)
from src.core.config_manager import ConfigManager, Config, ProxyConfig, ApiKeys
from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    ModuleResult,
)


class TestErrorHandler:
    """Tests for error handling classes."""

    def test_ats_exception_format(self):
        """Test basic exception formatting."""
        exc = AtsException(
            code="ERR_TEST",
            message="Test error message",
            remediation="Try fixing it"
        )
        assert exc.code == "ERR_TEST"
        assert exc.message == "Test error message"
        assert exc.remediation == "Try fixing it"
        assert "[ERR_TEST]" in str(exc)

    def test_ats_exception_to_dict(self):
        """Test exception serialization."""
        exc = AtsException(
            code="ERR_TEST",
            message="Test",
            remediation="Fix",
            details={"key": "value"}
        )
        d = exc.to_dict()
        assert d["code"] == "ERR_TEST"
        assert d["details"]["key"] == "value"

    def test_module_not_found_error(self):
        """Test module not found with suggestions."""
        exc = ModuleNotFoundError(
            "sqlmapp",
            available_modules=["sqlmap_wrapper", "nuclei_scanner", "nmap_scan"]
        )
        assert exc.code == "ERR_MODULE_NOT_FOUND"
        assert "sqlmapp" in exc.message
        # Should suggest similar module
        assert "sqlmap" in exc.remediation.lower()

    def test_api_key_missing_error(self):
        """Test API key missing error."""
        exc = APIKeyMissingError("shodan")
        assert exc.code == "ERR_API_KEY_MISSING"
        assert "shodan" in exc.message.lower()
        assert "ATS_API_SHODAN" in exc.remediation

    def test_validation_error(self):
        """Test validation error."""
        exc = ValidationError(
            field="username",
            value="ab",
            constraint="3-32 characters",
            expected="string of 3-32 chars"
        )
        assert exc.code == "ERR_VALIDATION_FAILED"
        assert "username" in exc.message
        assert "ab" in exc.message

    def test_execution_error(self):
        """Test execution error with original exception."""
        original = ValueError("Something went wrong")
        exc = ExecutionError(
            module_name="test_module",
            reason="Network failure",
            original_error=original
        )
        assert exc.code == "ERR_EXECUTION_FAILED"
        assert "test_module" in exc.message
        assert exc.details["original_type"] == "ValueError"


class TestConfigManager:
    """Tests for configuration management."""

    def test_default_config(self):
        """Test default configuration values."""
        config = Config()
        assert config.env == "development"
        assert config.threads == 50
        assert config.timeout == 60
        assert config.api_port == 8000

    def test_proxy_config(self):
        """Test proxy configuration."""
        proxy = ProxyConfig(
            enabled=True,
            host="proxy.example.com",
            port=8080,
            username="user",
            password="pass"
        )
        assert proxy.url == "http://user:pass@proxy.example.com:8080"

    def test_proxy_disabled(self):
        """Test disabled proxy returns None."""
        proxy = ProxyConfig(enabled=False)
        assert proxy.url is None

    def test_api_keys(self):
        """Test API keys management."""
        keys = ApiKeys(shodan="test_key_123")
        assert keys.get("shodan") == "test_key_123"
        assert keys.is_configured("shodan") is True
        assert keys.is_configured("hunter") is False

    def test_config_manager_with_env_file(self):
        """Test loading config from .env file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("ATS_ENV=production\n")
            f.write("ATS_THREADS=100\n")
            f.write("ATS_API_SHODAN=test_shodan_key\n")
            env_path = Path(f.name)

        try:
            manager = ConfigManager(env_file=env_path)
            assert manager.config.env == "production"
            assert manager.config.threads == 100
            assert manager.get_api_key("shodan") == "test_shodan_key"
        finally:
            env_path.unlink()

    def test_config_get_nested(self):
        """Test getting nested config values."""
        manager = ConfigManager()
        # Should return default values
        assert manager.get("env") == "development"
        assert manager.get("nonexistent", "default") == "default"

    def test_config_set_runtime(self):
        """Test setting runtime config."""
        manager = ConfigManager()
        manager.set("custom_key", "custom_value")
        assert manager.get("custom_key") == "custom_value"

    def test_config_to_dict(self):
        """Test config serialization."""
        manager = ConfigManager()
        d = manager.to_dict()
        assert "env" in d
        assert "threads" in d
        assert "api_keys" not in d  # secrets excluded by default

        d_with_secrets = manager.to_dict(include_secrets=True)
        assert "api_keys" in d_with_secrets


class TestParameter:
    """Tests for parameter validation."""

    def test_string_parameter(self):
        """Test string parameter validation."""
        param = Parameter(
            name="username",
            type=ParameterType.STRING,
            description="Username",
            min_length=3,
            max_length=32
        )

        valid, msg = param.validate("john_doe")
        assert valid is True

        valid, msg = param.validate("ab")
        assert valid is False
        assert "at least 3" in msg

    def test_integer_parameter(self):
        """Test integer parameter validation."""
        param = Parameter(
            name="port",
            type=ParameterType.INTEGER,
            description="Port number",
            min_value=1,
            max_value=65535
        )

        valid, msg = param.validate(8080)
        assert valid is True

        valid, msg = param.validate(70000)
        assert valid is False

    def test_choice_parameter(self):
        """Test choice parameter validation."""
        param = Parameter(
            name="protocol",
            type=ParameterType.CHOICE,
            description="Protocol",
            choices=["http", "https", "ftp"]
        )

        valid, msg = param.validate("https")
        assert valid is True

        valid, msg = param.validate("smtp")
        assert valid is False

    def test_required_parameter(self):
        """Test required parameter validation."""
        param = Parameter(
            name="target",
            type=ParameterType.STRING,
            description="Target",
            required=True
        )

        valid, msg = param.validate(None)
        assert valid is False
        assert "required" in msg

    def test_optional_parameter(self):
        """Test optional parameter validation."""
        param = Parameter(
            name="timeout",
            type=ParameterType.INTEGER,
            description="Timeout",
            required=False,
            default=60
        )

        valid, msg = param.validate(None)
        assert valid is True


class TestModuleSpec:
    """Tests for module specification."""

    def test_module_spec_creation(self):
        """Test creating a module spec."""
        spec = ModuleSpec(
            name="test_module",
            category=ModuleCategory.OSINT,
            description="Test module for unit tests",
            parameters=[
                Parameter(
                    name="target",
                    type=ParameterType.STRING,
                    description="Target"
                )
            ]
        )

        assert spec.name == "test_module"
        assert spec.category == ModuleCategory.OSINT
        assert len(spec.parameters) == 1

    def test_module_spec_to_dict(self):
        """Test spec serialization."""
        spec = ModuleSpec(
            name="test_module",
            category=ModuleCategory.PENTEST,
            description="Test",
            tags=["web", "injection"]
        )

        d = spec.to_dict()
        assert d["name"] == "test_module"
        assert d["category"] == "pentest"
        assert "web" in d["tags"]


class TestModuleResult:
    """Tests for module result."""

    def test_success_result(self):
        """Test successful result."""
        result = ModuleResult(
            success=True,
            data={"found": ["site1", "site2"]},
            duration_ms=1500
        )

        assert result.success is True
        assert len(result.data["found"]) == 2
        assert result.duration_ms == 1500

    def test_error_result(self):
        """Test error result."""
        result = ModuleResult(
            success=False,
            data={},
            errors=["Connection timeout", "API rate limited"],
            duration_ms=500
        )

        assert result.success is False
        assert len(result.errors) == 2

    def test_result_to_dict(self):
        """Test result serialization."""
        result = ModuleResult(
            success=True,
            data={"key": "value"},
            warnings=["Partial results"]
        )

        d = result.to_dict()
        assert d["success"] is True
        assert d["data"]["key"] == "value"
        assert "Partial results" in d["warnings"]


class TestAtsModule:
    """Tests for abstract module base class."""

    def test_concrete_module_implementation(self):
        """Test implementing a concrete module."""

        class TestModule(AtsModule):
            def get_spec(self) -> ModuleSpec:
                return ModuleSpec(
                    name="test_concrete",
                    category=ModuleCategory.OSINT,
                    description="Test concrete module",
                    parameters=[
                        Parameter(
                            name="query",
                            type=ParameterType.STRING,
                            description="Search query",
                            required=True,
                            min_length=1
                        )
                    ]
                )

            def validate_inputs(self, config):
                if not config.get("query"):
                    return False, "Query is required"
                return True, ""

            async def execute(self, config):
                return {"results": [f"Result for: {config['query']}"]}

        module = TestModule()
        assert module.spec.name == "test_concrete"
        assert module.spec.category == ModuleCategory.OSINT

    @pytest.mark.asyncio
    async def test_module_run(self):
        """Test module execution."""

        class SimpleModule(AtsModule):
            def get_spec(self):
                return ModuleSpec(
                    name="simple",
                    category=ModuleCategory.OSINT,
                    description="Simple test module"
                )

            def validate_inputs(self, config):
                return True, ""

            async def execute(self, config):
                return {"status": "completed"}

        module = SimpleModule()
        result = await module.run({})

        assert result.success is True
        assert result.data["status"] == "completed"
        assert result.duration_ms >= 0

    @pytest.mark.asyncio
    async def test_module_validation_failure(self):
        """Test module with validation failure."""

        class ValidatingModule(AtsModule):
            def get_spec(self):
                return ModuleSpec(
                    name="validating",
                    category=ModuleCategory.OSINT,
                    description="Module with validation",
                    parameters=[
                        Parameter(
                            name="target",
                            type=ParameterType.STRING,
                            description="Target",
                            required=True
                        )
                    ]
                )

            def validate_inputs(self, config):
                return True, ""

            async def execute(self, config):
                return {}

        module = ValidatingModule()
        result = await module.run({})  # Missing required 'target'

        assert result.success is False
        assert len(result.errors) > 0
