"""Simple deterministic full-text search over documents."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .errors import DocumentNotFound
from .storage import list_document_paths, read_document


@dataclass(frozen=True)
class SearchHit:
    """One search result with a short context window."""

    name: str
    score: int
    snippet: str


def _snippet(text: str, query: str, radius: int = 60) -> str:
    lowered = text.lower()
    index = lowered.find(query.lower())
    if index < 0:
        return text[: radius * 2].replace("\n", " ").strip()
    start = max(0, index - radius)
    end = min(len(text), index + len(query) + radius)
    snippet = text[start:end].replace("\n", " ").strip()
    prefix = "…" if start else ""
    suffix = "…" if end < len(text) else ""
    return prefix + snippet + suffix


def search_documents(
    root: Path,
    query: str,
    suffixes: tuple[str, ...],
    limit: int = 20,
) -> list[SearchHit]:
    """Return documents containing ``query``, ordered by occurrence count."""

    needle = query.strip().lower()
    if not needle:
        return []
    hits: list[SearchHit] = []
    for path in list_document_paths(root, suffixes):
        name = path.relative_to(Path(root)).as_posix()
        try:
            document = read_document(root, name)
        except (DocumentNotFound, OSError, UnicodeDecodeError):
            continue
        lowered = document.text.lower()
        score = lowered.count(needle)
        if score <= 0:
            continue
        hits.append(
            SearchHit(
                name=name,
                score=score,
                snippet=_snippet(document.text, query),
            )
        )
    hits.sort(key=lambda hit: (-hit.score, hit.name))
    return hits[:limit]


def first_match(root: Path, query: str, suffixes: tuple[str, ...]) -> SearchHit | None:
    """Return the highest-scoring hit, or ``None`` for an empty result set."""

    hits = search_documents(root, query, suffixes, limit=1)
    return hits[0] if hits else None
