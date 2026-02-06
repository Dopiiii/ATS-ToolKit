"""
Tests for user management endpoints.
"""

import pytest
from httpx import AsyncClient

from src.models.user import User


class TestListUsers:
    """Tests for listing users."""

    async def test_list_users_admin(
        self, client: AsyncClient, admin_headers: dict, test_user: User
    ):
        """Test admin can list users."""
        response = await client.get(
            "/api/v1/users",
            headers=admin_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert "data" in data
        assert "pagination" in data
        assert len(data["data"]) >= 1

    async def test_list_users_non_admin(
        self, client: AsyncClient, auth_headers: dict
    ):
        """Test non-admin cannot list users."""
        response = await client.get(
            "/api/v1/users",
            headers=auth_headers,
        )

        assert response.status_code == 403

    async def test_list_users_filter_role(
        self, client: AsyncClient, admin_headers: dict
    ):
        """Test filtering users by role."""
        response = await client.get(
            "/api/v1/users?role=admin",
            headers=admin_headers,
        )

        assert response.status_code == 200
        data = response.json()
        for user in data["data"]:
            assert user["role"] == "admin"


class TestCreateUser:
    """Tests for creating users."""

    async def test_create_user_admin(
        self, client: AsyncClient, admin_headers: dict
    ):
        """Test admin can create users."""
        response = await client.post(
            "/api/v1/users",
            headers=admin_headers,
            json={
                "email": "newuser@example.com",
                "password": "SecurePass123",
                "role": "analyst",
                "is_active": True,
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "newuser@example.com"
        assert data["role"] == "analyst"

    async def test_create_user_non_admin(
        self, client: AsyncClient, auth_headers: dict
    ):
        """Test non-admin cannot create users."""
        response = await client.post(
            "/api/v1/users",
            headers=auth_headers,
            json={
                "email": "newuser@example.com",
                "password": "SecurePass123",
                "role": "analyst",
            },
        )

        assert response.status_code == 403


class TestUpdateUser:
    """Tests for updating users."""

    async def test_update_user_admin(
        self, client: AsyncClient, admin_headers: dict, test_user: User
    ):
        """Test admin can update users."""
        response = await client.patch(
            f"/api/v1/users/{test_user.id}",
            headers=admin_headers,
            json={
                "role": "viewer",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["role"] == "viewer"


class TestDeleteUser:
    """Tests for deleting users."""

    async def test_delete_user_admin(
        self, client: AsyncClient, admin_headers: dict, test_user: User
    ):
        """Test admin can delete users."""
        response = await client.delete(
            f"/api/v1/users/{test_user.id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

    async def test_delete_self_forbidden(
        self, client: AsyncClient, admin_headers: dict, admin_user: User
    ):
        """Test admin cannot delete themselves."""
        response = await client.delete(
            f"/api/v1/users/{admin_user.id}",
            headers=admin_headers,
        )

        assert response.status_code == 409


class TestAPIKeys:
    """Tests for API key management."""

    async def test_create_api_key(
        self, client: AsyncClient, auth_headers: dict
    ):
        """Test creating an API key."""
        response = await client.post(
            "/api/v1/users/me/api-keys",
            headers=auth_headers,
            json={
                "name": "Test Key",
                "scopes": ["collections:read", "entities:read"],
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert "key" in data
        assert data["key"].startswith("osint_")
        assert data["name"] == "Test Key"

    async def test_list_api_keys(
        self, client: AsyncClient, auth_headers: dict
    ):
        """Test listing API keys."""
        # First create a key
        await client.post(
            "/api/v1/users/me/api-keys",
            headers=auth_headers,
            json={
                "name": "Test Key",
                "scopes": ["collections:read"],
            },
        )

        # List keys
        response = await client.get(
            "/api/v1/users/me/api-keys",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data["keys"]) >= 1

    async def test_delete_api_key(
        self, client: AsyncClient, auth_headers: dict
    ):
        """Test deleting an API key."""
        # Create key
        create_response = await client.post(
            "/api/v1/users/me/api-keys",
            headers=auth_headers,
            json={
                "name": "Test Key",
                "scopes": ["collections:read"],
            },
        )
        key_id = create_response.json()["id"]

        # Delete key
        response = await client.delete(
            f"/api/v1/users/me/api-keys/{key_id}",
            headers=auth_headers,
        )

        assert response.status_code == 200

    async def test_api_key_authentication(
        self, client: AsyncClient, auth_headers: dict
    ):
        """Test authenticating with an API key."""
        # Create key
        create_response = await client.post(
            "/api/v1/users/me/api-keys",
            headers=auth_headers,
            json={
                "name": "Auth Test Key",
                "scopes": ["*"],
            },
        )
        api_key = create_response.json()["key"]

        # Use API key for authentication
        response = await client.get(
            "/api/v1/auth/me",
            headers={"X-API-Key": api_key},
        )

        assert response.status_code == 200
        assert response.json()["email"] == "test@example.com"
