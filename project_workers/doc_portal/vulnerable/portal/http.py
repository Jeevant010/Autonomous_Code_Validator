"""A small in-process request router.

It is intentionally not a network server. The functional tests exercise the
same routing, validation, and service calls without opening a port.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

from .auth import Principal
from .errors import AuthError, PortalError
from .render import render_error, render_index
from .service import DocumentService


@dataclass(frozen=True)
class Request:
    method: str
    path: str
    body: str = ""
    principal: Principal | None = None


@dataclass(frozen=True)
class Response:
    status: int
    body: str
    content_type: str = "text/plain; charset=utf-8"


def _json(value: object, status: int = 200) -> Response:
    return Response(
        status=status,
        body=json.dumps(value, sort_keys=True),
        content_type="application/json",
    )


def _route_parts(path: str) -> tuple[list[str], dict[str, list[str]]]:
    parsed = urlparse(path)
    parts = [part for part in parsed.path.split("/") if part]
    return parts, parse_qs(parsed.query)


def route(service: DocumentService, request: Request) -> Response:
    """Dispatch a request and convert domain errors into responses."""

    parts, query = _route_parts(request.path)
    try:
        if request.method == "GET" and parts == ["documents"]:
            return _json({"documents": [item.__dict__ for item in service.list()]})
        if request.method == "GET" and len(parts) == 2 and parts[0] == "documents":
            return Response(status=200, body=service.render(parts[1]), content_type="text/html")
        if request.method == "GET" and len(parts) == 2 and parts[0] == "search":
            hits = service.search(query.get("q", [""])[0])
            return _json({"hits": [hit.__dict__ for hit in hits]})
        if request.method == "GET" and parts == ["stats"]:
            return _json(service.stats().__dict__)
        if request.method == "GET" and parts == ["index"]:
            names = [item.name for item in service.list()]
            return Response(status=200, body=render_index(names), content_type="text/html")
        if request.method == "POST" and len(parts) == 2 and parts[0] == "documents":
            if request.principal is None:
                raise AuthError("write requests need a principal")
            service.write(parts[1], request.body, request.principal)
            return _json({"ok": True, "name": parts[1]}, status=201)
        if request.method == "DELETE" and len(parts) == 2 and parts[0] == "documents":
            if request.principal is None:
                raise AuthError("delete requests need a principal")
            service.delete(parts[1], request.principal)
            return _json({"ok": True})
        if request.method == "GET" and parts == ["health"]:
            return _json({"ok": True, "documents": len(service.list())})
        raise PortalError(f"no route for {request.method} {request.path}")
    except AuthError as exc:
        return _json({"error": str(exc)}, status=403)
    except PortalError as exc:
        return Response(status=404, body=render_error(str(exc)), content_type="text/html")
    except OSError as exc:
        return _json({"error": str(exc)}, status=500)
