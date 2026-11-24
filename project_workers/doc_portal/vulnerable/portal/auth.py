"""Small token and role helpers for the in-process portal router."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass

from .errors import AuthError

TOKEN_BYTES = 24
SALT_BYTES = 16
HASH_ROUNDS = 120_000


@dataclass(frozen=True)
class Principal:
    """The identity attached to a request."""

    name: str
    role: str = "reader"

    def require(self, role: str) -> None:
        if self.role != role and self.role != "admin":
            raise AuthError(f"{self.name!r} does not have the {role!r} role")

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


def new_salt(size: int = SALT_BYTES) -> str:
    return secrets.token_urlsafe(size)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def hash_token(secret: str, salt: str, rounds: int = HASH_ROUNDS) -> str:
    """Derive a stable verifier from a bearer token and a salt."""

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        secret.encode("utf-8"),
        salt.encode("utf-8"),
        rounds,
    )
    return _b64(digest)


def issue_token(principal: Principal, secret: str) -> str:
    """Create a compact token for an in-process test or CLI session."""

    salt = new_salt()
    verifier = hash_token(secret, salt)
    payload = f"{principal.name}:{principal.role}:{salt}:{verifier}"
    return _b64(payload.encode("utf-8"))


def verify_token(token: str, secret: str) -> Principal:
    """Verify a token and return its principal."""

    if not token:
        raise AuthError("empty token")
    try:
        raw = _unb64(token).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise AuthError("token is not valid base64") from exc
    parts = raw.split(":")
    if len(parts) != 4:
        raise AuthError("token has the wrong number of fields")
    name, role, salt, verifier = parts
    expected = hash_token(secret, salt)
    if not hmac.compare_digest(expected, verifier):
        raise AuthError("token verifier does not match")
    return Principal(name=name, role=role)


def random_password(size: int = TOKEN_BYTES) -> str:
    """Generate a password for local setup scripts."""

    return secrets.token_urlsafe(size)
