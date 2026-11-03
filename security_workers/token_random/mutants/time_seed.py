from __future__ import annotations

import random
import string
import time

ALPHABET = string.ascii_letters + string.digits
random.seed(time.time())


def reset_token(length: int = 24) -> str:
    return "".join(random.choices(ALPHABET, k=length))
