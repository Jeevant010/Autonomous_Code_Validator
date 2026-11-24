"""Render documents as small, escaped HTML fragments."""

from __future__ import annotations

import html
from pathlib import PurePosixPath


def _title(name: str) -> str:
    return PurePosixPath(name).stem.replace("-", " ").replace("_", " ").title()


def render_document(name: str, text: str) -> str:
    """Return an HTML fragment with both name and body escaped."""

    safe_name = html.escape(name, quote=True)
    safe_title = html.escape(_title(name), quote=True)
    safe_text = html.escape(text, quote=False)
    return (
        f'<article class="document" data-name="{safe_name}">'
        f"<h1>{safe_title}</h1><pre>{safe_text}</pre></article>"
    )


def render_index(entries: list[str]) -> str:
    """Render a navigation list for the landing page."""

    items = "".join(
        f'<li><a href="/documents/{html.escape(name, quote=True)}">'
        f"{html.escape(name)}</a></li>"
        for name in entries
    )
    return f'<nav class="documents"><ul>{items}</ul></nav>'


def render_error(message: str) -> str:
    """Render a plain error fragment without interpolating raw HTML."""

    return f'<p class="error">{html.escape(message)}</p>'
