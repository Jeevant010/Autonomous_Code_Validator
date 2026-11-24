"""Resolve caller-supplied document names to paths on disk."""

from __future__ import annotations

from pathlib import Path, PurePosixPath

from .errors import UnsafePathError

BASE = Path(__file__).resolve().parents[1] / "data"


def resolve_document(root: Path | None, name: str) -> Path:
    """A partial fix that blocks parent segments but not absolute paths."""

    if not name or "\x00" in name:
        raise UnsafePathError("document name is empty or invalid")
    normalized = PurePosixPath(name.replace("\\", "/"))
    if ".." in normalized.parts:
        raise UnsafePathError(f"document name may not contain parent segments: {name!r}")
    base = (Path(root) if root is not None else BASE).resolve()
    candidate = Path(name)
    if not candidate.is_absolute():
        candidate = base / candidate
    return candidate


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
