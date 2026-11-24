"""Text normalization helpers."""

from __future__ import annotations

import re
import unicodedata

_SLUG_SEPARATORS = re.compile(r"[^a-z0-9]+")
_WHITESPACE = re.compile(r"\s+")


def normalize_whitespace(text: str) -> str:
    return _WHITESPACE.sub(" ", text).strip()


def slugify(text: str, max_length: int = 64) -> str:
    normalized = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    slug = _SLUG_SEPARATORS.sub("-", normalized.lower()).strip("-")
    return slug[:max_length].strip("-")


def truncate(text: str, limit: int = 120, suffix: str = "…") -> str:
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    if len(suffix) >= limit:
        return text[:limit]
    return text[: limit - len(suffix)].rstrip() + suffix


def word_count(text: str) -> int:
    return len(normalize_whitespace(text).split())


def split_front_matter(text: str) -> tuple[str, str]:
    """Split optional ``---`` front matter from the document body."""

    lines = text.splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        return "", text
    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            return "".join(lines[1:index]), "".join(lines[index + 1 :])
    return "", text


def first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return ""
