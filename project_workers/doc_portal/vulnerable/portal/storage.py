"""Read, write, list, and delete documents on disk."""

from __future__ import annotations

from pathlib import Path

from .errors import DocumentNotFound, DocumentTooLarge
from .models import Document
from .paths import ensure_parent, resolve_document
from .util.time import utc_now

DEFAULT_MAX_BYTES = 128_000


def _decode(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def read_document(
    root: Path,
    name: str,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> Document:
    """Read a document and return its content and metadata."""

    path = resolve_document(root, name)
    if not path.is_file():
        raise DocumentNotFound(f"document not found: {name}")
    size = path.stat().st_size
    if size > max_bytes:
        raise DocumentTooLarge(f"document is larger than {max_bytes} bytes: {name}")
    text = _decode(path)
    modified = path.stat().st_mtime
    return Document(
        name=name,
        text=text,
        size=size,
        updated_at=_format_mtime(modified),
    )


def write_document(
    root: Path,
    name: str,
    text: str,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> Document:
    """Write a document, creating parent directories as needed."""

    encoded = text.encode("utf-8")
    if len(encoded) > max_bytes:
        raise DocumentTooLarge(f"document is larger than {max_bytes} bytes: {name}")
    path = ensure_parent(resolve_document(root, name))
    path.write_text(text, encoding="utf-8")
    return read_document(root, name, max_bytes=max_bytes)


def delete_document(root: Path, name: str) -> None:
    """Delete a document if it exists."""

    path = resolve_document(root, name)
    if not path.is_file():
        raise DocumentNotFound(f"document not found: {name}")
    path.unlink()


def list_document_paths(root: Path, suffixes: tuple[str, ...]) -> list[Path]:
    """Return all regular document files below ``root``."""

    base = Path(root)
    if not base.is_dir():
        return []
    paths: list[Path] = []
    for path in sorted(base.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        if path.suffix.lower() in suffixes:
            paths.append(path)
    return paths


def _format_mtime(value: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def touch_document(root: Path, name: str) -> None:
    """Update a document's mtime, or fail if it does not exist."""

    path = resolve_document(root, name)
    if not path.is_file():
        raise DocumentNotFound(f"document not found: {name}")
    path.touch()


def document_size(root: Path, name: str) -> int:
    """Return a document's size without reading its content."""

    path = resolve_document(root, name)
    if not path.is_file():
        raise DocumentNotFound(f"document not found: {name}")
    return path.stat().st_size


def current_timestamp() -> str:
    """Expose a stable timestamp helper for callers that do not import util."""

    return utc_now()
