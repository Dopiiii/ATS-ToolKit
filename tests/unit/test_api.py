"""Unit tests for FastAPI endpoints."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

# Mock the registry before importing the app
@pytest.fixture
def mock_registry():
    """Create a mock registry."""
    from src.core.base_module import ModuleSpec, ModuleCategory

    mock = MagicMock()
    mock.count = 5
    mock.discover.return_value = 5

    spec = ModuleSpec(
        name="test_module",
        category=ModuleCategory.OSINT,
        description="Test module"
    )

    mock.list_modules.return_value = [spec]
    mock.list_categories.return_value = {ModuleCategory.OSINT: 5}
    mock.get_spec.return_value = spec
    mock.search.return_value = [spec]

    return mock


@pytest.fixture
def client(mock_registry):
    """Create test client with mocked dependencies."""
    with patch('src.api.main.get_registry', return_value=mock_registry):
        with patch('src.api.main.init_config'):
            with patch('src.api.main.setup_logging'):
                from src.api.main import app
                with TestClient(app) as client:
                    yield client


class TestHealthEndpoint:
    """Tests for health check endpoint."""

    def test_health_check(self, client, mock_registry):
        """Test health endpoint returns correct status."""
        response = client.get("/health")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "healthy"
        assert data["version"] == "2.0.0"
        assert "modules_loaded" in data


class TestModuleEndpoints:
    """Tests for module-related endpoints."""

    def test_list_modules(self, client, mock_registry):
        """Test listing all modules."""
        response = client.get("/modules")
        assert response.status_code == 200

        data = response.json()
        assert "modules" in data
        assert "total" in data

    def test_list_modules_with_category(self, client, mock_registry):
        """Test listing modules filtered by category."""
        response = client.get("/modules?category=osint")
        assert response.status_code == 200

    def test_list_modules_with_search(self, client, mock_registry):
        """Test searching modules."""
        response = client.get("/modules?search=test")
        assert response.status_code == 200

    def test_list_categories(self, client, mock_registry):
        """Test listing categories with counts."""
        response = client.get("/modules/categories")
        assert response.status_code == 200

        data = response.json()
        assert "categories" in data

    def test_get_module_spec(self, client, mock_registry):
        """Test getting module specification."""
        response = client.get("/modules/test_module")
        assert response.status_code == 200

        data = response.json()
        assert data["name"] == "test_module"

    def test_get_module_not_found(self, client, mock_registry):
        """Test getting non-existent module."""
        from src.core.error_handler import ModuleNotFoundError as AtsModuleNotFoundError
        mock_registry.get_spec.side_effect = AtsModuleNotFoundError("nonexistent", [])

        response = client.get("/modules/nonexistent")
        assert response.status_code == 404


class TestConfigEndpoints:
    """Tests for configuration endpoints."""

    def test_get_config(self, client):
        """Test getting configuration."""
        with patch('src.api.main.get_config') as mock_config:
            mock_config.return_value.to_dict.return_value = {
                "env": "development",
                "threads": 50
            }

            response = client.get("/config")
            assert response.status_code == 200

    def test_update_config(self, client):
        """Test updating configuration."""
        with patch('src.api.main.get_config') as mock_config:
            mock_instance = MagicMock()
            mock_config.return_value = mock_instance

            response = client.post(
                "/config/test_key",
                json={"value": "test_value"}
            )
            assert response.status_code == 200
            mock_instance.set.assert_called_once()

    def test_reload_config(self, client):
        """Test reloading configuration."""
        with patch('src.api.main.get_config') as mock_config:
            mock_instance = MagicMock()
            mock_config.return_value = mock_instance

            response = client.post("/config/reload")
            assert response.status_code == 200
            mock_instance.reload.assert_called_once()


class TestModuleExecution:
    """Tests for module execution endpoint."""

    @pytest.mark.asyncio
    async def test_run_module_success(self, client, mock_registry):
        """Test successful module execution."""
        from src.core.base_module import ModuleResult

        mock_result = ModuleResult(
            success=True,
            data={"results": ["item1", "item2"]},
            duration_ms=1000
        )

        async def mock_execute(*args, **kwargs):
            return mock_result

        mock_registry.execute = mock_execute

        response = client.post(
            "/modules/test_module/run",
            json={"config": {"target": "example.com"}}
        )
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert "results" in data["data"]

    @pytest.mark.asyncio
    async def test_run_module_with_timeout(self, client, mock_registry):
        """Test module execution with custom timeout."""
        from src.core.base_module import ModuleResult

        mock_result = ModuleResult(success=True, data={}, duration_ms=500)

        async def mock_execute(*args, **kwargs):
            return mock_result

        mock_registry.execute = mock_execute

        response = client.post(
            "/modules/test_module/run",
            json={"config": {}, "timeout": 30}
        )
        assert response.status_code == 200
