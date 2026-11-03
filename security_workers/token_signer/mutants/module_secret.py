from __future__ import annotations

import hashlib
import hmac
import os

DEBUG_KEY = "acv-dev-secret"


def _secret() -> bytes:
    return os.environ.get("ACV_TOKEN_SECRET", DEBUG_KEY).encode()


def sign(value: str) -> str:
    return hmac.new(_secret(), value.encode(), hashlib.sha256).hexdigest()


def verify(value: str, signature: str) -> bool:
    return hmac.compare_digest(sign(value), signature)
