"""
SQLAlchemy models for the OSINT Platform.

Phase 1 Models:
- User: User accounts with roles
- APIKey: API keys for programmatic access
- AuditLog: Audit trail of all actions

Phase 2+ Models (defined later):
- Entity: OSINT entities (people, domains, IPs, etc.)
- Relationship: Connections between entities
- Collection: Data collection jobs
"""

from src.models.api_key import APIKey
from src.models.audit import AuditLog
from src.models.user import User, UserRole

__all__ = [
    "User",
    "UserRole",
    "APIKey",
    "AuditLog",
]
