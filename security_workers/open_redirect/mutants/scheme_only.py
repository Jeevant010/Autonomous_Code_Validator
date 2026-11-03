from __future__ import annotations

from urllib.parse import urlparse


def next_url(target: str | None) -> str:
    if not target:
        return "/"
    parsed = urlparse(target)
    if parsed.scheme and parsed.hostname != "app.local":
        return "/"
    return target
