from __future__ import annotations


def render_comment(author: str, body: str) -> str:
    return f"<article><h2>{author}</h2><p>{body}</p></article>"
