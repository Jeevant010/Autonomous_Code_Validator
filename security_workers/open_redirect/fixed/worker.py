from __future__ import annotations

from urllib.parse import urlparse

ALLOWED_HOSTS = {"app.local"}


def next_url(target: str | None) -> str:
    if not target:
        return "/"
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        if parsed.hostname not in ALLOWED_HOSTS:
            return "/"
    return target
