from __future__ import annotations

import hashlib
import hmac
import os

KEY_NAME = "ACV_TOKEN_SECRET"


def _key() -> bytes:
    raw = os.environ.get(KEY_NAME)
    if raw is None or len(raw) < 16:
        raise RuntimeError("missing or short key")
    return raw.encode()


def sign(value: str) -> str:
    return hmac.new(_key(), value.encode(), hashlib.sha256).hexdigest()


def verify(value: str, signature: str) -> bool:
    return hmac.compare_digest(sign(value), signature)
