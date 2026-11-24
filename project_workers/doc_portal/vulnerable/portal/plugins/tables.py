"""Render simple fixed-width tables for terminal output."""

from __future__ import annotations


def _widths(rows: list[list[str]]) -> list[int]:
    if not rows:
        return []
    columns = max(len(row) for row in rows)
    widths = [0] * columns
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    return widths


def render_table(rows: list[list[str]], padding: int = 2) -> str:
    if not rows:
        return ""
    widths = _widths(rows)
    lines: list[str] = []
    for row in rows:
        cells = [
            cell.ljust(widths[index])
            for index, cell in enumerate(row)
        ]
        lines.append((" " * padding).join(cells).rstrip())
    return "\n".join(lines) + "\n"


def render_key_values(values: dict[str, object]) -> str:
    rows = [[str(key), str(value)] for key, value in sorted(values.items())]
    return render_table(rows)
