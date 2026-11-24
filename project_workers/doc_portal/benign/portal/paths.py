"""Resolve caller-supplied document names to paths on disk."""

from __future__ import annotations

import os
from pathlib import Path

from .errors import UnsafePathError

BASE = Path(__file__).resolve().parents[1] / "data"


def resolve_document(root: Path | None, name: str) -> Path:
    """Use realpath plus commonpath instead of Path.is_relative_to."""

    if not name or "\x00" in name:
        raise UnsafePathError("document name is empty or invalid")
    base = os.path.realpath(root if root is not None else BASE)
    candidate = os.path.realpath(os.path.join(base, name))
    try:
        common = os.path.commonpath([base, candidate])
    except ValueError as exc:
        raise UnsafePathError(f"document path is not comparable: {name!r}") from exc
    if common != base or candidate == base:
        raise UnsafePathError(f"document escapes the document root: {name!r}")
    return Path(candidate)


def display_name(root: Path, path: Path) -> str:
    base = Path(root).resolve()
    resolved = path.resolve()
    try:
        return resolved.relative_to(base).as_posix()
    except ValueError:
        return resolved.name


def sibling_path(path: Path, suffix: str) -> Path:
    if not suffix.startswith("."):
        suffix = "." + suffix
    return path.with_suffix(suffix)


def ensure_parent(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    return path
