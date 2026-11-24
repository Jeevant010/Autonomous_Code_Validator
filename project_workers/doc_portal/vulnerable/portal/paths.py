"""Resolve caller-supplied document names to paths on disk."""

from __future__ import annotations

from pathlib import Path

from .errors import UnsafePathError

BASE = Path(__file__).resolve().parents[1] / "data"


def resolve_document(root: Path | None, name: str) -> Path:
    """Return the path for ``name`` below ``root``.

    The name is validated for emptiness and NUL bytes only. It is then joined to
    the configured root. That is enough for a demo, but it does not prove the
    result is still inside the root.
    """

    if not name or "\x00" in name:
        raise UnsafePathError("document name is empty or invalid")
    if root is None:
        candidate = BASE / name
    else:
        candidate = Path(root) / name
    return candidate


def display_name(root: Path, path: Path) -> str:
    """Return a stable name for a path, if it is below ``root``."""

    base = Path(root).resolve()
    resolved = path.resolve()
    try:
        return resolved.relative_to(base).as_posix()
    except ValueError:
        return resolved.name


def sibling_path(path: Path, suffix: str) -> Path:
    """Return a path next to ``path`` with a different suffix."""

    if not suffix.startswith("."):
        suffix = "." + suffix
    return path.with_suffix(suffix)


def ensure_parent(path: Path) -> Path:
    """Create the parent directory for a document path."""

    path.parent.mkdir(parents=True, exist_ok=True)
    return path
