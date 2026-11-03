from __future__ import annotations

import hashlib
import hmac
import os

ENV_KEY = "ACV_TOKEN_SECRET"


def _secret() -> bytes:
    value = os.environ.get(ENV_KEY)
    if not value:
        raise RuntimeError("ACV_TOKEN_SECRET is not set")
    return value.encode()


def sign(value: str) -> str:
    return hmac.new(_secret(), value.encode(), hashlib.sha256).hexdigest()


def verify(value: str, signature: str) -> bool:
    return hmac.compare_digest(sign(value), signature)
