from __future__ import annotations


def next_url(target: str | None) -> str:
    if not target:
        return "/"
    if target.startswith("/") or target.startswith("https://app.local"):
        return target
    return "/"
