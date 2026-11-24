"""Small utilities shared by the portal modules."""

from __future__ import annotations

from .text import normalize_whitespace, slugify, truncate, word_count
from .time import format_timestamp, utc_now

__all__ = [
    "format_timestamp",
    "normalize_whitespace",
    "slugify",
    "truncate",
    "utc_now",
    "word_count",
]
