"""Behaviour that must keep working after the CVE-2023-32681 fix.

Proxy authorization for plain HTTP must still work: the fix must only stop the
leak for tunnelled HTTPS requests, not remove proxy authentication entirely.
"""

from __future__ import annotations

import base64


from requests.models import PreparedRequest
from requests.sessions import Session


def _prepared(url: str = "http://origin.internal/data") -> PreparedRequest:
    request = PreparedRequest()
    request.prepare(url=url, method="GET", headers={"Accept": "*/*"})
    return request


def test_http_proxy_auth_is_still_attached() -> None:
    session = Session()
    request = _prepared()
    session.rebuild_proxies(request, {"http": "http://user:pass@proxy.internal:3128"})

    header = request.headers.get("Proxy-Authorization")
    assert header is not None
    assert base64.b64encode(b"user:pass").decode() in header


def test_https_proxy_auth_is_reported_by_the_poc() -> None:
    # The leak itself is the PoC's job, not the behaviour suite's. This test
    # only pins that the code path exists and does not raise on https.
    session = Session()
    request = _prepared("https://origin.internal/data")
    session.rebuild_proxies(request, {"https": "https://user:pass@proxy.internal:3128"})


def test_proxy_without_credentials_adds_no_header() -> None:
    session = Session()
    request = _prepared()
    session.rebuild_proxies(request, {"http": "http://proxy.internal:3128"})

    assert "Proxy-Authorization" not in request.headers


def test_proxies_are_still_resolved() -> None:
    session = Session()
    request = _prepared()
    proxies = session.rebuild_proxies(
        request, {"http": "http://user:pass@proxy.internal:3128"}
    )

    assert proxies["http"] == "http://user:pass@proxy.internal:3128"


def test_stale_header_is_replaced() -> None:
    session = Session()
    request = _prepared()
    request.headers["Proxy-Authorization"] = "Basic stale"
    session.rebuild_proxies(request, {"http": "http://user:pass@proxy.internal:3128"})

    assert request.headers["Proxy-Authorization"] != "Basic stale"

