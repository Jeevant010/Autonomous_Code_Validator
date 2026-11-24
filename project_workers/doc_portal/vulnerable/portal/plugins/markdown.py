"""Tiny Markdown builders used by export and preview commands."""

from __future__ import annotations


def heading(text: str, level: int = 1) -> str:
    depth = min(max(level, 1), 6)
    return f"{'#' * depth} {text.strip()}\n"


def unordered_list(items: list[str]) -> str:
    return "".join(f"- {item.strip()}\n" for item in items)


def ordered_list(items: list[str]) -> str:
    return "".join(f"{index}. {item.strip()}\n" for index, item in enumerate(items, start=1))


def code_block(text: str, language: str = "") -> str:
    fence = "```"
    return f"{fence}{language}\n{text.rstrip()}\n{fence}\n"


def link(label: str, target: str) -> str:
    return f"[{label.strip()}]({target.strip()})"


def blockquote(text: str) -> str:
    return "".join(f"> {line}\n" for line in text.splitlines())
