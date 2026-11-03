from __future__ import annotations

import urllib.request


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=3) as response:
        return response.read().decode("utf-8")
