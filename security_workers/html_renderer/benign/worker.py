from __future__ import annotations

import html


def render_comment(author: str, body: str) -> str:
    return "<article><h2>{}</h2><p>{}</p></article>".format(
        html.escape(author),
        html.escape(body),
    )
