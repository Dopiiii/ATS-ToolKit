"""
User management service.

Handles:
- User CRUD operations
- API key management
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.core.exceptions import ConflictError, NotFoundError
from src.core.logging import get_logger, log_audit
from src.core.security import generate_api_key, get_password_hash, hash_api_key
from src.models.api_key import APIKey
from src.models.audit import AuditActions
from src.models.user import User, UserRole
from src.schemas.common import PaginationParams, create_pagination_meta
from src.schemas.user import APIKeyCreate, UserCreate, UserUpdate

logger = get_logger(__name__)


class UserService:
    """User and API key management service."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # =========================================================================
    # User Operations
    # =========================================================================

    async def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        result = await self.db.execute(
            select(User)
            .options(selectinload(User.api_keys))
            .where(User.id == user_id)
        )
        return result.scalar_one_or_none()

    async def get_user_or_404(self, user_id: str) -> User:
        """Get user by ID or raise NotFoundError."""
        user = await self.get_user(user_id)
        if not user:
            raise NotFoundError(resource="User", resource_id=user_id)
        return user

    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        result = await self.db.execute(
            select(User).where(User.email == email.lower())
        )
        return result.scalar_one_or_none()

    async def list_users(
        self,
        pagination: PaginationParams,
        role: Optional[UserRole] = None,
        is_active: Optional[bool] = None,
    ) -> dict:
        """
        List users with pagination and filters.

        Returns:
            Dict with 'data' and 'pagination' keys
        """
        # Build query
        query = select(User)

        if role:
            query = query.where(User.role == role.value)
        if is_active is not None:
            query = query.where(User.is_active == is_active)

        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total = (await self.db.execute(count_query)).scalar() or 0

        # Apply pagination
        query = query.offset(pagination.offset).limit(pagination.limit)
        query = query.order_by(User.created_at.desc())

        result = await self.db.execute(query)
        users = result.scalars().all()

        return {
            "data": users,
            "pagination": create_pagination_meta(
                pagination.page, pagination.per_page, total
            ),
        }

    async def create_user(
        self,
        data: UserCreate,
        created_by: Optional[str] = None,
    ) -> User:
        """
        Create a new user (admin only).

        Args:
            data: User creation data
            created_by: Admin user ID creating this user

        Returns:
            Created user
        """
        # Check if email exists
        existing = await self.get_user_by_email(data.email)
        if existing:
            raise ConflictError(
                message="Email already registered",
                code="email_exists",
            )

        user = User(
            email=data.email.lower(),
            password_hash=get_password_hash(data.password),
            role=data.role.value,
            is_active=data.is_active,
            is_verified=True,  # Admin-created users are pre-verified
        )

        self.db.add(user)
        await self.db.flush()

        log_audit(
            action=AuditActions.USER_CREATE,
            user_id=created_by,
            resource_type="user",
            resource_id=user.id,
            email=user.email,
            role=user.role,
        )

        logger.info(
            "User created by admin",
            user_id=user.id,
            created_by=created_by,
        )

        return user

    async def update_user(
        self,
        user_id: str,
        data: UserUpdate,
        updated_by: Optional[str] = None,
    ) -> User:
        """
        Update a user.

        Args:
            user_id: User ID to update
            data: Update data
            updated_by: User ID performing the update

        Returns:
            Updated user
        """
        user = await self.get_user_or_404(user_id)

        # Track changes for audit
        changes = {}

        if data.email is not None and data.email != user.email:
            # Check if new email is taken
            existing = await self.get_user_by_email(data.email)
            if existing:
                raise ConflictError(
                    message="Email already in use",
                    code="email_exists",
                )
            changes["email"] = {"from": user.email, "to": data.email}
            user.email = data.email.lower()

        if data.role is not None and data.role.value != user.role:
            changes["role"] = {"from": user.role, "to": data.role.value}
            user.role = data.role.value

        if data.is_active is not None and data.is_active != user.is_active:
            changes["is_active"] = {"from": user.is_active, "to": data.is_active}
            user.is_active = data.is_active

        if changes:
            log_audit(
                action=AuditActions.USER_UPDATE,
                user_id=updated_by,
                resource_type="user",
                resource_id=user.id,
                changes=changes,
            )

            logger.info(
                "User updated",
                user_id=user.id,
                updated_by=updated_by,
                changes=list(changes.keys()),
            )

        return user

    async def delete_user(
        self,
        user_id: str,
        deleted_by: Optional[str] = None,
    ) -> bool:
        """
        Delete a user.

        Args:
            user_id: User ID to delete
            deleted_by: Admin user ID performing deletion

        Returns:
            True if deleted
        """
        user = await self.get_user_or_404(user_id)

        # Prevent self-deletion
        if user_id == deleted_by:
            raise ConflictError(
                message="Cannot delete your own account",
                code="cannot_delete_self",
            )

        email = user.email
        await self.db.delete(user)

        log_audit(
            action=AuditActions.USER_DELETE,
            user_id=deleted_by,
            resource_type="user",
            resource_id=user_id,
            email=email,
        )

        logger.info(
            "User deleted",
            user_id=user_id,
            deleted_by=deleted_by,
        )

        return True

    # =========================================================================
    # API Key Operations
    # =========================================================================

    async def list_api_keys(self, user_id: str) -> list[APIKey]:
        """List all API keys for a user."""
        result = await self.db.execute(
            select(APIKey)
            .where(APIKey.user_id == user_id)
            .order_by(APIKey.created_at.desc())
        )
        return list(result.scalars().all())

    async def create_api_key(
        self,
        user_id: str,
        data: APIKeyCreate,
        ip_address: Optional[str] = None,
    ) -> tuple[APIKey, str]:
        """
        Create a new API key.

        Args:
            user_id: Owner user ID
            data: API key creation data
            ip_address: Client IP for audit

        Returns:
            Tuple of (APIKey model, plain text key)
            The plain text key is only returned once!
        """
        # Generate the key
        plain_key = generate_api_key()
        key_hash = hash_api_key(plain_key)

        # Calculate expiration
        expires_at = None
        if data.expires_in_days:
            expires_at = datetime.now(timezone.utc) + timedelta(days=data.expires_in_days)

        api_key = APIKey(
            user_id=user_id,
            key_hash=key_hash,
            name=data.name,
            scopes=data.scopes,
            expires_at=expires_at,
            is_active=True,
        )

        self.db.add(api_key)
        await self.db.flush()

        log_audit(
            action=AuditActions.API_KEY_CREATE,
            user_id=user_id,
            resource_type="api_key",
            resource_id=api_key.id,
            ip_address=ip_address,
            name=data.name,
            scopes=data.scopes,
        )

        logger.info(
            "API key created",
            user_id=user_id,
            api_key_id=api_key.id,
            name=data.name,
        )

        return api_key, plain_key

    async def get_api_key(self, key_id: str, user_id: str) -> Optional[APIKey]:
        """Get API key by ID (must belong to user)."""
        result = await self.db.execute(
            select(APIKey).where(
                APIKey.id == key_id,
                APIKey.user_id == user_id,
            )
        )
        return result.scalar_one_or_none()

    async def delete_api_key(
        self,
        key_id: str,
        user_id: str,
        ip_address: Optional[str] = None,
    ) -> bool:
        """
        Delete an API key.

        Args:
            key_id: API key ID
            user_id: Owner user ID
            ip_address: Client IP for audit

        Returns:
            True if deleted
        """
        api_key = await self.get_api_key(key_id, user_id)
        if not api_key:
            raise NotFoundError(resource="API Key", resource_id=key_id)

        name = api_key.name
        await self.db.delete(api_key)

        log_audit(
            action=AuditActions.API_KEY_DELETE,
            user_id=user_id,
            resource_type="api_key",
            resource_id=key_id,
            ip_address=ip_address,
            name=name,
        )

        logger.info(
            "API key deleted",
            user_id=user_id,
            api_key_id=key_id,
        )

        return True

    async def validate_api_key(
        self,
        plain_key: str,
        required_scope: Optional[str] = None,
    ) -> Optional[tuple[APIKey, User]]:
        """
        Validate an API key and return the key and owner.

        Args:
            plain_key: Plain text API key
            required_scope: Optional scope to check

        Returns:
            Tuple of (APIKey, User) if valid, None otherwise
        """
        # Get all active keys (we need to check each one since we hash)
        result = await self.db.execute(
            select(APIKey)
            .options(selectinload(APIKey.user))
            .where(APIKey.is_active == True)  # noqa: E712
        )
        keys = result.scalars().all()

        for api_key in keys:
            from src.core.security import verify_api_key

            if verify_api_key(plain_key, api_key.key_hash):
                # Check if expired
                if api_key.is_expired:
                    continue

                # Check scope if required
                if required_scope and not api_key.has_scope(required_scope):
                    continue

                # Check if user is active
                if not api_key.user.is_active:
                    continue

                # Update last used
                api_key.last_used = datetime.now(timezone.utc)

                return api_key, api_key.user

        return None
