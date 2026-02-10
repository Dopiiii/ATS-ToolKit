"""Honey token generator module.

Generate trackable honey tokens including fake credentials, API keys,
documents, and email addresses with embedded tracking identifiers.
"""

import asyncio
import hashlib
import secrets
import string
import uuid
from typing import Any, Dict, List, Tuple

from src.core.base_module import (
    AtsModule,
    ModuleSpec,
    ModuleCategory,
    Parameter,
    ParameterType,
    OutputField,
)

# Character sets for realistic token generation
AWS_KEY_PREFIX = "AKIA"
AWS_KEY_CHARS = string.ascii_uppercase + string.digits
API_KEY_CHARS = string.ascii_letters + string.digits
PASSWORD_CHARS = string.ascii_letters + string.digits + "!@#$%^&*"


def _generate_aws_key(identifier: str) -> Dict[str, str]:
    """Generate a realistic-looking fake AWS access key pair."""
    key_id = AWS_KEY_PREFIX + "".join(secrets.choice(AWS_KEY_CHARS) for _ in range(16))
    secret_raw = "".join(secrets.choice(API_KEY_CHARS + "+/") for _ in range(40))
    tracking_hash = hashlib.sha256(f"aws:{identifier}:{key_id}".encode()).hexdigest()[:12]
    return {
        "access_key_id": key_id,
        "secret_access_key": secret_raw,
        "tracking_hash": tracking_hash,
    }


def _generate_api_key(identifier: str) -> Dict[str, str]:
    """Generate a realistic fake API key."""
    prefix = secrets.choice(["sk-", "pk_live_", "api_", "key-", "tok_"])
    body = "".join(secrets.choice(API_KEY_CHARS) for _ in range(32))
    token = f"{prefix}{body}"
    tracking_hash = hashlib.sha256(f"api:{identifier}:{token}".encode()).hexdigest()[:12]
    return {"api_key": token, "tracking_hash": tracking_hash}


def _generate_password(identifier: str) -> Dict[str, str]:
    """Generate a realistic fake password."""
    length = secrets.choice(range(12, 20))
    password = "".join(secrets.choice(PASSWORD_CHARS) for _ in range(length))
    tracking_hash = hashlib.sha256(f"pwd:{identifier}:{password}".encode()).hexdigest()[:12]
    return {"password": password, "tracking_hash": tracking_hash}


def _generate_document(identifier: str) -> Dict[str, str]:
    """Generate metadata for a decoy document token."""
    doc_id = str(uuid.uuid4())
    tracking_hash = hashlib.sha256(f"doc:{identifier}:{doc_id}".encode()).hexdigest()[:12]
    return {
        "document_id": doc_id,
        "suggested_filename": f"confidential_report_{doc_id[:8]}.pdf",
        "embedded_marker": tracking_hash,
        "tracking_hash": tracking_hash,
    }


def _generate_email(identifier: str) -> Dict[str, str]:
    """Generate a unique trackable email address."""
    uid = uuid.uuid4().hex[:10]
    email = f"admin-{uid}@internal-alerts.example.com"
    tracking_hash = hashlib.sha256(f"email:{identifier}:{email}".encode()).hexdigest()[:12]
    return {"email": email, "tracking_hash": tracking_hash}


TOKEN_GENERATORS = {
    "aws_key": _generate_aws_key,
    "api_key": _generate_api_key,
    "password": _generate_password,
    "document": _generate_document,
    "email": _generate_email,
}


class HoneyTokenGeneratorModule(AtsModule):
    """Generate trackable honey tokens for deception operations."""

    def get_spec(self) -> ModuleSpec:
        return ModuleSpec(
            name="honey_token_generator",
            category=ModuleCategory.DECEPTION,
            description="Generate trackable honey tokens such as fake credentials, API keys, and documents with embedded tracking identifiers",
            version="1.0.0",
            parameters=[
                Parameter(
                    name="token_type",
                    type=ParameterType.CHOICE,
                    description="Type of honey token to generate",
                    required=True,
                    choices=["aws_key", "api_key", "password", "document", "email"],
                ),
                Parameter(
                    name="quantity",
                    type=ParameterType.INTEGER,
                    description="Number of tokens to generate",
                    required=False,
                    default=5,
                    min_value=1,
                    max_value=100,
                ),
                Parameter(
                    name="identifier",
                    type=ParameterType.STRING,
                    description="Campaign or deployment identifier for tracking",
                    required=True,
                ),
            ],
            outputs=[
                OutputField(name="tokens", type="list", description="Generated honey tokens with tracking data"),
                OutputField(name="tracking_metadata", type="dict", description="Metadata for tracking token usage"),
            ],
            tags=["deception", "honey-token", "credentials", "tracking"],
            author="ATS-Toolkit",
            requires_api_key=False,
            api_key_service=None,
            dangerous=False,
        )

    def validate_inputs(self, config: Dict[str, Any]) -> Tuple[bool, str]:
        token_type = config.get("token_type", "")
        if token_type not in TOKEN_GENERATORS:
            return False, f"Invalid token_type: {token_type}"
        identifier = config.get("identifier", "").strip()
        if not identifier:
            return False, "identifier is required"
        quantity = config.get("quantity", 5)
        if not isinstance(quantity, int) or quantity < 1:
            return False, "quantity must be a positive integer"
        return True, ""

    async def execute(self, config: Dict[str, Any]) -> Dict[str, Any]:
        token_type = config["token_type"]
        quantity = config.get("quantity", 5)
        identifier = config["identifier"].strip()

        self.logger.info("generating_honey_tokens", type=token_type, quantity=quantity)

        generator = TOKEN_GENERATORS[token_type]
        tokens = []
        for i in range(quantity):
            token_data = generator(f"{identifier}-{i}")
            token_data["index"] = i
            token_data["token_type"] = token_type
            tokens.append(token_data)

        tracking_metadata = {
            "campaign_id": identifier,
            "token_type": token_type,
            "total_generated": len(tokens),
            "tracking_hashes": [t["tracking_hash"] for t in tokens],
        }

        self.logger.info("honey_tokens_generated", count=len(tokens))

        return {
            "tokens": tokens,
            "tracking_metadata": tracking_metadata,
        }
