from __future__ import annotations

import urllib.request
from urllib.parse import urlparse

BLOCKED = {"169.254.169.254"}


def fetch(url: str) -> str:
    parsed = urlparse(url)
    if parsed.hostname in BLOCKED:
        raise ValueError("metadata endpoint blocked")
    with urllib.request.urlopen(url, timeout=3) as response:
        return response.read().decode("utf-8")
