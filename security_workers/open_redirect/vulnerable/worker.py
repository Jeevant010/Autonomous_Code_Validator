from __future__ import annotations


def next_url(target: str | None) -> str:
    if target:
        return target
    return "/"
