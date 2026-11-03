from __future__ import annotations

import html


def render_comment(author: str, body: str) -> str:
    safe = html.escape(body, quote=True).replace("&lt;", "<").replace("&gt;", ">")
    return f"<article><h2>{author}</h2><p>{safe}</p></article>"
