"""
Tests for health check endpoints.
"""

import pytest
from httpx import AsyncClient


class TestHealthCheck:
    """Tests for health check endpoints."""

    async def test_health_check(self, client: AsyncClient):
        """Test health check endpoint."""
        response = await client.get("/api/v1/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["healthy", "degraded"]
        assert "version" in data
        assert "database" in data

    async def test_api_root(self, client: AsyncClient):
        """Test API root endpoint."""
        response = await client.get("/api/v1/")

        assert response.status_code == 200
        data = response.json()
        assert "name" in data
        assert "version" in data

    async def test_app_root(self, client: AsyncClient):
        """Test application root endpoint."""
        response = await client.get("/")

        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "docs" in data
