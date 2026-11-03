from __future__ import annotations


def render_comment(author: str, body: str) -> str:
    safe = body.replace("<script>", "").replace("</script>", "")
    return f"<article><h2>{author}</h2><p>{safe}</p></article>"
