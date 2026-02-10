"""
Tests for authentication endpoints.
"""

import pytest
from httpx import AsyncClient

from src.models.user import User


class TestRegister:
    """Tests for user registration."""

    async def test_register_success(self, client: AsyncClient):
        """Test successful registration."""
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "SecurePass123",
                "password_confirm": "SecurePass123",
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "newuser@example.com"
        assert data["role"] == "analyst"
        assert "id" in data

    async def test_register_duplicate_email(self, client: AsyncClient, test_user: User):
        """Test registration with existing email."""
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": test_user.email,
                "password": "SecurePass123",
                "password_confirm": "SecurePass123",
            },
        )

        assert response.status_code == 409
        assert "email_exists" in response.json()["error"]["code"]

    async def test_register_password_mismatch(self, client: AsyncClient):
        """Test registration with mismatched passwords."""
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "SecurePass123",
                "password_confirm": "DifferentPass123",
            },
        )

        assert response.status_code == 422

    async def test_register_weak_password(self, client: AsyncClient):
        """Test registration with weak password."""
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "weak",
                "password_confirm": "weak",
            },
        )

        assert response.status_code == 422


class TestLogin:
    """Tests for user login."""

    async def test_login_success(self, client: AsyncClient, test_user: User):
        """Test successful login."""
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": test_user.email,
                "password": "TestPass123",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    async def test_login_invalid_password(self, client: AsyncClient, test_user: User):
        """Test login with wrong password."""
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": test_user.email,
                "password": "WrongPassword123",
            },
        )

        assert response.status_code == 401
        assert "invalid_credentials" in response.json()["error"]["code"]

    async def test_login_nonexistent_user(self, client: AsyncClient):
        """Test login with non-existent email."""
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "nonexistent@example.com",
                "password": "SomePassword123",
            },
        )

        assert response.status_code == 401
        assert "invalid_credentials" in response.json()["error"]["code"]


class TestRefreshToken:
    """Tests for token refresh."""

    async def test_refresh_success(self, client: AsyncClient, test_user: User):
        """Test successful token refresh."""
        # First login
        login_response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": test_user.email,
                "password": "TestPass123",
            },
        )
        refresh_token = login_response.json()["refresh_token"]

        # Refresh
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    async def test_refresh_invalid_token(self, client: AsyncClient):
        """Test refresh with invalid token."""
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "invalid-token"},
        )

        assert response.status_code == 401


class TestCurrentUser:
    """Tests for current user endpoint."""

    async def test_get_current_user(self, client: AsyncClient, auth_headers: dict):
        """Test getting current user profile."""
        response = await client.get(
            "/api/v1/auth/me",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["email"] == "test@example.com"
        assert data["role"] == "analyst"

    async def test_get_current_user_unauthenticated(self, client: AsyncClient):
        """Test getting current user without auth."""
        response = await client.get("/api/v1/auth/me")

        assert response.status_code == 401


class TestChangePassword:
    """Tests for password change."""

    async def test_change_password_success(
        self, client: AsyncClient, test_user: User, auth_headers: dict
    ):
        """Test successful password change."""
        response = await client.post(
            "/api/v1/auth/change-password",
            headers=auth_headers,
            json={
                "current_password": "TestPass123",
                "new_password": "NewSecurePass456",
                "new_password_confirm": "NewSecurePass456",
            },
        )

        assert response.status_code == 200

        # Verify new password works
        login_response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": test_user.email,
                "password": "NewSecurePass456",
            },
        )
        assert login_response.status_code == 200

    async def test_change_password_wrong_current(
        self, client: AsyncClient, auth_headers: dict
    ):
        """Test password change with wrong current password."""
        response = await client.post(
            "/api/v1/auth/change-password",
            headers=auth_headers,
            json={
                "current_password": "WrongPassword123",
                "new_password": "NewSecurePass456",
                "new_password_confirm": "NewSecurePass456",
            },
        )

        assert response.status_code == 401
