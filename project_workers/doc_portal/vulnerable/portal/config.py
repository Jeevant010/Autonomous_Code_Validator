"""Configuration values for the document portal."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

DEFAULT_SUFFIXES = (".md", ".txt", ".rst", ".html")
DEFAULT_MAX_DOCUMENT_BYTES = 128_000
DEFAULT_PAGE_SIZE = 20


@dataclass(frozen=True)
class Settings:
    """Runtime settings shared by the service and its callers."""

    root: Path
    max_document_bytes: int = DEFAULT_MAX_DOCUMENT_BYTES
    suffixes: tuple[str, ...] = DEFAULT_SUFFIXES
    page_size: int = DEFAULT_PAGE_SIZE
    read_only: bool = False

    def resolved_root(self) -> Path:
        return self.root.resolve()

    def accepts(self, name: str) -> bool:
        return Path(name).suffix.lower() in self.suffixes

    def with_root(self, root: Path) -> Settings:
        return Settings(
            root=root,
            max_document_bytes=self.max_document_bytes,
            suffixes=self.suffixes,
            page_size=self.page_size,
            read_only=self.read_only,
        )

    def with_read_only(self, read_only: bool) -> Settings:
        return Settings(
            root=self.root,
            max_document_bytes=self.max_document_bytes,
            suffixes=self.suffixes,
            page_size=self.page_size,
            read_only=read_only,
        )
