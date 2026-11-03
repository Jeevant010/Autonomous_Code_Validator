from __future__ import annotations

import random
import string

ALPHABET = string.ascii_letters + string.digits
random.seed(1337)


def reset_token(length: int = 24) -> str:
    return "".join(random.choices(ALPHABET, k=length))
