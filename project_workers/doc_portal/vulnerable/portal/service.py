"""Service facade that composes storage, search, rendering, and auth."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .auth import Principal
from .config import Settings
from .errors import DocumentNotFound, InvalidRequest
from .models import Document, DocumentSummary, PortalStats
from .render import render_document
from .search import SearchHit, search_documents
from .storage import (
    delete_document,
    list_document_paths,
    read_document,
    write_document,
)
from .util.text import slugify


@dataclass
class DocumentService:
    """The main entry point used by the HTTP router and the CLI."""

    settings: Settings

    def __post_init__(self) -> None:
        self.settings.root.mkdir(parents=True, exist_ok=True)

    def list(self) -> list[DocumentSummary]:
        summaries: list[DocumentSummary] = []
        for path in list_document_paths(self.settings.root, self.settings.suffixes):
            name = path.relative_to(self.settings.resolved_root()).as_posix()
            summaries.append(
                DocumentSummary(
                    name=name,
                    size=path.stat().st_size,
                    line_count=_line_count(path),
                )
            )
        return summaries

    def read(self, name: str) -> Document:
        _require_name(name)
        return read_document(
            self.settings.root,
            name,
            max_bytes=self.settings.max_document_bytes,
        )

    def write(self, name: str, text: str, principal: Principal | None = None) -> Document:
        _require_name(name)
        if principal is not None:
            principal.require("writer")
        if self.settings.read_only:
            raise InvalidRequest("the portal is read-only")
        return write_document(
            self.settings.root,
            name,
            text,
            max_bytes=self.settings.max_document_bytes,
        )

    def delete(self, name: str, principal: Principal | None = None) -> None:
        _require_name(name)
        if principal is not None:
            principal.require("writer")
        if self.settings.read_only:
            raise InvalidRequest("the portal is read-only")
        delete_document(self.settings.root, name)

    def search(self, query: str, limit: int | None = None) -> list[SearchHit]:
        if not query.strip():
            return []
        return search_documents(
            self.settings.root,
            query,
            self.settings.suffixes,
            limit=limit or self.settings.page_size,
        )

    def render(self, name: str) -> str:
        document = self.read(name)
        return render_document(document.name, document.text)

    def stats(self) -> PortalStats:
        summaries = self.list()
        total = sum(item.size for item in summaries)
        newest = max((item.name for item in summaries), default=None)
        return PortalStats(
            documents=len(summaries),
            total_bytes=total,
            newest=newest,
            read_only=self.settings.read_only,
        )

    def suggest_name(self, title: str, suffix: str = ".md") -> str:
        base = slugify(title) or "untitled"
        if not suffix.startswith("."):
            suffix = "." + suffix
        candidate = base + suffix
        index = 2
        while (self.settings.resolved_root() / candidate).exists():
            candidate = f"{base}-{index}{suffix}"
            index += 1
        return candidate

    def export_index(self) -> dict[str, object]:
        return {
            "documents": [item.__dict__ for item in self.list()],
            "stats": self.stats().__dict__,
        }

    def require(self, name: str) -> Document:
        try:
            return self.read(name)
        except DocumentNotFound:
            raise
        except OSError as exc:
            raise InvalidRequest(f"could not read {name!r}: {exc}") from exc


def _require_name(name: str) -> None:
    if not name or not name.strip():
        raise InvalidRequest("document name is required")


def _line_count(path: Path) -> int:
    try:
        return len(path.read_text(encoding="utf-8").splitlines())
    except (OSError, UnicodeDecodeError):
        return 0
