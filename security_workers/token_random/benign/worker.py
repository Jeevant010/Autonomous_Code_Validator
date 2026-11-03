from __future__ import annotations

import secrets
import string

ALPHABET = string.ascii_letters + string.digits


def reset_token(length: int = 24) -> str:
    generated = []
    for _ in range(length):
        generated.append(secrets.choice(ALPHABET))
    return "".join(generated)
