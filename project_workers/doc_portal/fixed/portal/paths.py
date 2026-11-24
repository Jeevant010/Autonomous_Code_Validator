"""Resolve caller-supplied document names to paths on disk."""

from __future__ import annotations

from pathlib import Path

from .errors import UnsafePathError

BASE = Path(__file__).resolve().parents[1] / "data"


def resolve_document(root: Path | None, name: str) -> Path:
    """Return a resolved path that is proven to stay inside ``root``.

    Both the root and the candidate are resolved first, so ``..`` segments and
    symlinks are interpreted before the containment check. An absolute
    ``name`` is therefore also contained.
    """

    if not name or "\x00" in name:
        raise UnsafePathError("document name is empty or invalid")
    base = (Path(root) if root is not None else BASE).resolve()
    candidate = (base / name).resolve()
    if not candidate.is_relative_to(base):
        raise UnsafePathError(f"document escapes the document root: {name!r}")
    if candidate == base:
        raise UnsafePathError("document name resolves to the document root")
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
