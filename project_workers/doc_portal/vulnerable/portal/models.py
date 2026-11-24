"""Immutable records returned by the document service."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Document:
    """A document with its content and basic metadata."""

    name: str
    text: str
    size: int
    updated_at: str

    @property
    def line_count(self) -> int:
        return len(self.text.splitlines())

    def summary(self) -> DocumentSummary:
        return DocumentSummary(name=self.name, size=self.size, line_count=self.line_count)


@dataclass(frozen=True)
class DocumentSummary:
    """The part of a document shown in listings and search results."""

    name: str
    size: int
    line_count: int


@dataclass(frozen=True)
class PortalStats:
    """Aggregate information used by the landing page and health checks."""

    documents: int
    total_bytes: int
    newest: str | None
    read_only: bool
