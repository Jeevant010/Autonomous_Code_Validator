"""Functional tests for normal document-portal behaviour.

These tests deliberately do not assert the security boundary. The exploit does
that. The purpose here is to make sure a repair did not break ordinary use.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from portal.auth import Principal, issue_token, verify_token
from portal.config import Settings
from portal.errors import DocumentNotFound
from portal.http import Request, route
from portal.plugins import code_block, heading, render_table
from portal.render import render_document
from portal.service import DocumentService


@pytest.fixture()
def service(tmp_path: Path) -> DocumentService:
    root = tmp_path / "documents"
    root.mkdir()
    return DocumentService(Settings(root=root))


def test_write_and_read(service: DocumentService) -> None:
    service.write("welcome.md", "# Welcome\n\nHello.\n")
    document = service.read("welcome.md")
    assert document.text.startswith("# Welcome")
    assert document.line_count >= 3


def test_nested_document(service: DocumentService) -> None:
    service.write("guides/install.md", "Install it.\n")
    assert service.read("guides/install.md").text == "Install it.\n"
    assert "guides/install.md" in [item.name for item in service.list()]


def test_list_documents(service: DocumentService) -> None:
    service.write("a.md", "alpha\n")
    service.write("b.txt", "beta\n")
    names = [item.name for item in service.list()]
    assert names == ["a.md", "b.txt"]


def test_search_hits(service: DocumentService) -> None:
    service.write("one.md", "alpha beta beta\n")
    service.write("two.md", "alpha only\n")
    hits = service.search("beta")
    assert [hit.name for hit in hits] == ["one.md"]
    assert hits[0].score == 2


def test_render_escapes_html(service: DocumentService) -> None:
    service.write("safe.md", "<script>alert(1)</script>")
    rendered = service.render("safe.md")
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered


def test_missing_document(service: DocumentService) -> None:
    with pytest.raises(DocumentNotFound):
        service.read("missing.md")


def test_http_router_round_trip(service: DocumentService) -> None:
    principal = Principal(name="alice", role="writer")
    created = route(
        service,
        Request(method="POST", path="/documents/note.md", body="hello", principal=principal),
    )
    assert created.status == 201
    listed = route(service, Request(method="GET", path="/documents"))
    assert listed.status == 200
    assert "note.md" in listed.body
    fetched = route(service, Request(method="GET", path="/documents/note.md"))
    assert fetched.status == 200
    assert "hello" in fetched.body


def test_auth_round_trip() -> None:
    token = issue_token(Principal(name="bob", role="reader"), "local-test-secret")
    principal = verify_token(token, "local-test-secret")
    assert principal.name == "bob"
    assert principal.role == "reader"


def test_plugin_helpers() -> None:
    assert heading("Title") == "# Title\n"
    assert "```python" in code_block("print(1)", "python")
    assert "name" in render_table([["name", "value"], ["a", "1"]])


def test_stats(service: DocumentService) -> None:
    service.write("a.md", "abc")
    service.write("b.md", "defg")
    stats = service.stats()
    assert stats.documents == 2
    assert stats.total_bytes == 7
    assert stats.newest == "b.md"


def test_render_document_helper() -> None:
    rendered = render_document("note.md", "a < b")
    assert "note" in rendered
    assert "a &lt; b" in rendered
