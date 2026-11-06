from __future__ import annotations

import urllib.error
import urllib.request
from urllib.parse import urlparse

ALLOWED_HOSTS = {"localhost"}


def _allowed(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and parsed.hostname in ALLOWED_HOSTS


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> urllib.request.Request | None:
        if not _allowed(newurl):
            raise urllib.error.HTTPError(
                newurl,
                code,
                "redirect host is not allowed",
                headers,  # type: ignore[arg-type]
                fp,  # type: ignore[arg-type]
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)  # type: ignore[arg-type]


def fetch(url: str) -> str:
    if not _allowed(url):
        raise ValueError("URL is not allowed")
    opener = urllib.request.build_opener(_SafeRedirectHandler)
    with opener.open(url, timeout=3) as response:
        return response.read().decode("utf-8")
