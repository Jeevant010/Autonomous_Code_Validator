from __future__ import annotations

import urllib.request
from urllib.parse import urlparse

ALLOWED_HOSTS = frozenset({"localhost"})


def fetch(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("unsupported scheme")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("host is not allowed")
    request = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(request, timeout=3) as response:
        return response.read().decode("utf-8")
