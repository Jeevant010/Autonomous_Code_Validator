from __future__ import annotations

import urllib.request
from urllib.parse import urlparse


def fetch(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("unsupported scheme")
    with urllib.request.urlopen(url, timeout=3) as response:
        return response.read().decode("utf-8")
