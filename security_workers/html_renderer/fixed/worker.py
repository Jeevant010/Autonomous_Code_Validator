from __future__ import annotations

import html


def render_comment(author: str, body: str) -> str:
    return (
        "<article><h2>"
        + html.escape(author)
        + "</h2><p>"
        + html.escape(body)
        + "</p></article>"
    )
