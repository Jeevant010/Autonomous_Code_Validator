"""Create the security worker pack.

The pack is deliberately small enough to inspect. Every task has a vulnerable
implementation, a reviewed fix, a safer variant, two known-bad variants, a
deterministic exploit, and a functional suite. The script is idempotent.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "security_workers"


def candidate(
    name: str, kind: str, path: str, expected_security: bool, note: str = ""
) -> dict[str, object]:
    return {
        "name": name,
        "kind": kind,
        "path": path,
        "expected_security": expected_security,
        "expected_behavior": True,
        "note": note,
    }


TASKS: list[dict[str, object]] = [
    {
        "id": "cmd_runner",
        "title": "Shell command runner",
        "cwe": "CWE-78",
        "summary": (
            "A worker concatenates user input into a shell command. "
            "The exploit appends a second command."
        ),
        "tags": ["python", "injection", "subprocess"],
        "files": {
            "vulnerable/worker.py": """from __future__ import annotations

import subprocess


def run_echo(value: str) -> str:
    completed = subprocess.run(
        "echo " + value,
        shell=True,
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.stdout
""",
            "fixed/worker.py": """from __future__ import annotations

import subprocess


def run_echo(value: str) -> str:
    completed = subprocess.run(
        ["echo", value],
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.stdout
""",
            "benign/worker.py": """from __future__ import annotations

import subprocess


def run_echo(value: str) -> str:
    process = subprocess.Popen(["echo", value], stdout=subprocess.PIPE, text=True)
    output, _ = process.communicate(timeout=5)
    return output
""",
            "mutants/semicolon_filter.py": """from __future__ import annotations

import subprocess


def run_echo(value: str) -> str:
    cleaned = value.replace(";", "")
    completed = subprocess.run("echo " + cleaned, shell=True, capture_output=True, text=True)
    return completed.stdout
""",
            "mutants/sh_c_filter.py": """from __future__ import annotations

import subprocess


def run_echo(value: str) -> str:
    cleaned = value.replace(";", "")
    completed = subprocess.run(["sh", "-c", "echo " + cleaned], capture_output=True, text=True)
    return completed.stdout
""",
            "poc/exploit.py": """from __future__ import annotations

import sys
from pathlib import Path

from worker import run_echo

MARKER = Path("ACV_CMD_PWNED")

try:
    MARKER.unlink(missing_ok=True)
    run_echo("hello; touch ACV_CMD_PWNED")
except Exception as exc:
    print(f"error: {exc}")
    sys.exit(2)

if MARKER.exists():
    MARKER.unlink(missing_ok=True)
    print("exploit: command injection")
    sys.exit(0)

print("blocked")
sys.exit(1)
""",
            "tests/test_functional.py": """from worker import run_echo


def test_echo() -> None:
    assert run_echo("hello") == "hello\\n"


def test_spaces() -> None:
    assert run_echo("hello world") == "hello world\\n"
""",
        },
        "candidates": [
            candidate("gold", "gold", "fixed/worker.py", True),
            candidate("benign", "benign", "benign/worker.py", True),
            candidate("semicolon_filter", "mutant", "mutants/semicolon_filter.py", False),
            candidate("sh_c_filter", "mutant", "mutants/sh_c_filter.py", False),
        ],
    },
    {
        "id": "path_reader",
        "title": "Sandboxed note reader",
        "cwe": "CWE-22",
        "summary": (
            "A file worker joins a user-supplied note name to a sandbox root "
            "and reads the result."
        ),
        "tags": ["python", "filesystem", "path"],
        "files": {
            "vulnerable/worker.py": """from __future__ import annotations

import os
from pathlib import Path

BASE = Path(os.environ["ACV_DATA_DIR"]) / "sandbox"


def read_note(name: str) -> str:
    return (BASE / name).read_text(encoding="utf-8")
""",
            "fixed/worker.py": """from __future__ import annotations

import os
from pathlib import Path

BASE = (Path(os.environ["ACV_DATA_DIR"]) / "sandbox").resolve()


def read_note(name: str) -> str:
    target = (BASE / name).resolve()
    if not target.is_relative_to(BASE):
        raise ValueError("path escapes sandbox")
    return target.read_text(encoding="utf-8")
""",
            "benign/worker.py": """from __future__ import annotations

import os

BASE = os.path.realpath(os.path.join(os.environ["ACV_DATA_DIR"], "sandbox"))


def read_note(name: str) -> str:
    target = os.path.realpath(os.path.join(BASE, name))
    if os.path.commonpath([BASE, target]) != BASE:
        raise ValueError("path escapes sandbox")
    with open(target, encoding="utf-8") as handle:
        return handle.read()
""",
            "mutants/prefix_filter.py": """from __future__ import annotations

import os
from pathlib import Path

BASE = Path(os.environ["ACV_DATA_DIR"]) / "sandbox"


def read_note(name: str) -> str:
    if name.startswith(".."):
        raise ValueError("blocked")
    return (BASE / name).read_text(encoding="utf-8")
""",
            "mutants/normpath_only.py": """from __future__ import annotations

import os
from pathlib import Path

BASE = Path(os.environ["ACV_DATA_DIR"]) / "sandbox"


def read_note(name: str) -> str:
    target = Path(os.path.normpath(BASE / name))
    return target.read_text(encoding="utf-8")
""",
            "poc/exploit.py": """from __future__ import annotations

import sys

from worker import read_note


try:
    content = read_note("../secret.txt")
except Exception:
    content = ""

if "ACV_SECRET" in content:
    print("exploit: path traversal")
    sys.exit(0)

print("blocked")
sys.exit(1)
""",
            "tests/test_functional.py": """from worker import read_note


def test_public_note() -> None:
    assert "public note" in read_note("notes.txt")


def test_nested_note() -> None:
    assert "nested note" in read_note("nested/note.txt")
""",
            "data/sandbox/notes.txt": "public note\n",
            "data/sandbox/nested/note.txt": "nested note\n",
            "data/secret.txt": "ACV_SECRET\n",
        },
        "candidates": [
            candidate("gold", "gold", "fixed/worker.py", True),
            candidate("benign", "benign", "benign/worker.py", True),
            candidate("prefix_filter", "mutant", "mutants/prefix_filter.py", False),
            candidate("normpath_only", "mutant", "mutants/normpath_only.py", False),
        ],
    },
    {
        "id": "sql_lookup",
        "title": "User lookup query",
        "cwe": "CWE-89",
        "summary": "A SQLite lookup interpolates a username into a query string.",
        "tags": ["python", "sqlite", "sql"],
        "files": {
            "vulnerable/worker.py": """from __future__ import annotations

import os
import sqlite3
from typing import Any

DB = os.path.join(os.environ["ACV_DATA_DIR"], "users.db")


def lookup(name: str) -> list[tuple[Any, ...]]:
    with sqlite3.connect(DB) as conn:
        query = f"SELECT username, role FROM users WHERE username = '{name}'"
        return conn.execute(query).fetchall()
""",
            "fixed/worker.py": """from __future__ import annotations

import os
import sqlite3
from typing import Any

DB = os.path.join(os.environ["ACV_DATA_DIR"], "users.db")


def lookup(name: str) -> list[tuple[Any, ...]]:
    with sqlite3.connect(DB) as conn:
        return conn.execute(
            "SELECT username, role FROM users WHERE username = ?",
            (name,),
        ).fetchall()
""",
            "benign/worker.py": """from __future__ import annotations

import os
import sqlite3
from typing import Any

DB = os.path.join(os.environ["ACV_DATA_DIR"], "users.db")


def lookup(name: str) -> list[tuple[Any, ...]]:
    cleaned = name.replace("'", "")
    query = f"SELECT username, role FROM users WHERE username = '{cleaned}'"
    with sqlite3.connect(DB) as conn:
        return conn.execute(query).fetchall()
""",
            "mutants/backslash_escape.py": """from __future__ import annotations

import os
import sqlite3
from typing import Any

DB = os.path.join(os.environ["ACV_DATA_DIR"], "users.db")


def lookup(name: str) -> list[tuple[Any, ...]]:
    escaped = name.replace("'", "\\\\'")
    query = f"SELECT username, role FROM users WHERE username = '{escaped}'"
    with sqlite3.connect(DB) as conn:
        return conn.execute(query).fetchall()
""",
            "mutants/string_concat.py": """from __future__ import annotations

import os
import sqlite3
from typing import Any

DB = os.path.join(os.environ["ACV_DATA_DIR"], "users.db")


def lookup(name: str) -> list[tuple[Any, ...]]:
    query = "SELECT username, role FROM users WHERE username = '" + name + "'"
    with sqlite3.connect(DB) as conn:
        return conn.execute(query).fetchall()
""",
            "poc/exploit.py": """from __future__ import annotations

import sys

from worker import lookup


try:
    rows = lookup("alice\\\\' OR 1=1 --")
except Exception as exc:
    print(f"error: {exc}")
    sys.exit(2)

if len(rows) >= 3:
    print(f"exploit: {len(rows)} rows returned")
    sys.exit(0)

print("blocked")
sys.exit(1)
""",
            "tests/test_functional.py": """from worker import lookup


def test_alice() -> None:
    assert lookup("alice") == [("alice", "admin")]


def test_bob() -> None:
    assert lookup("bob") == [("bob", "user")]


def test_missing() -> None:
    assert lookup("nobody") == []
""",
        },
        "candidates": [
            candidate("gold", "gold", "fixed/worker.py", True),
            candidate("benign", "benign", "benign/worker.py", True),
            candidate("backslash_escape", "mutant", "mutants/backslash_escape.py", False),
            candidate("string_concat", "mutant", "mutants/string_concat.py", False),
        ],
    },
    {
        "id": "pickle_loader",
        "title": "Profile deserializer",
        "cwe": "CWE-502",
        "summary": "A profile loader accepts pickle payloads and constructs arbitrary objects.",
        "tags": ["python", "deserialization", "pickle"],
        "files": {
            "vulnerable/worker.py": """from __future__ import annotations

import pickle


def load_profile(payload: bytes) -> dict:
    data = pickle.loads(payload)
    if not isinstance(data, dict):
        raise ValueError("profile must be a mapping")
    return data
""",
            "fixed/worker.py": """from __future__ import annotations

import io
import pickle

ALLOWED = {
    ("builtins", "dict"),
    ("builtins", "list"),
    ("builtins", "str"),
    ("builtins", "int"),
}


class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module: str, name: str) -> object:
        if (module, name) in ALLOWED:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"blocked class: {module}.{name}")


def load_profile(payload: bytes) -> dict:
    data = SafeUnpickler(io.BytesIO(payload)).load()
    if not isinstance(data, dict):
        raise ValueError("profile must be a mapping")
    return data
""",
            "benign/worker.py": """from __future__ import annotations

import io
import pickle

_ALLOWED = frozenset(
    {
        ("builtins", "dict"),
        ("builtins", "list"),
        ("builtins", "str"),
        ("builtins", "int"),
    }
)


class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module: str, name: str) -> object:
        if (module, name) not in _ALLOWED:
            raise pickle.UnpicklingError(f"blocked class: {module}.{name}")
        return super().find_class(module, name)


def load_profile(payload: bytes) -> dict:
    data = RestrictedUnpickler(io.BytesIO(payload)).load()
    if not isinstance(data, dict):
        raise ValueError("profile must be a mapping")
    return data
""",
            "mutants/filtered_pickle.py": """from __future__ import annotations

import pickle
import re


def load_profile(payload: bytes) -> dict:
    if re.search(rb"os|system|subprocess", payload):
        raise ValueError("blocked")
    data = pickle.loads(payload)
    if not isinstance(data, dict):
        raise ValueError("profile must be a mapping")
    return data
""",
            "mutants/length_guard.py": """from __future__ import annotations

import pickle


def load_profile(payload: bytes) -> dict:
    if len(payload) > 4096:
        raise ValueError("profile too large")
    data = pickle.loads(payload)
    if not isinstance(data, dict):
        raise ValueError("profile must be a mapping")
    return data
""",
            "poc/exploit.py": """from __future__ import annotations

import pickle
import sys
from pathlib import Path

from worker import load_profile

MARKER = Path("ACV_PICKLE_PWNED")


class Exploit:
    def __reduce__(self) -> tuple[object, tuple[str]]:
        return (
            eval,
            ("__import__('pathlib').Path('ACV_PICKLE_PWNED').write_text('pwned')",),
        )


try:
    MARKER.unlink(missing_ok=True)
    load_profile(pickle.dumps(Exploit()))
except Exception:
    pass

if MARKER.exists():
    MARKER.unlink(missing_ok=True)
    print("exploit: pickle code execution")
    sys.exit(0)

print("blocked")
sys.exit(1)
""",
            "tests/test_functional.py": """import pickle

from worker import load_profile


def test_profile() -> None:
    assert load_profile(pickle.dumps({"name": "alice"})) == {"name": "alice"}


def test_invalid() -> None:
    try:
        load_profile(b"not-a-pickle")
    except Exception:
        return
    raise AssertionError("expected an error")
""",
        },
        "candidates": [
            candidate("gold", "gold", "fixed/worker.py", True),
            candidate("benign", "benign", "benign/worker.py", True),
            candidate("filtered_pickle", "mutant", "mutants/filtered_pickle.py", False),
            candidate("length_guard", "mutant", "mutants/length_guard.py", False),
        ],
    },
    {
        "id": "url_fetcher",
        "title": "Remote URL fetcher",
        "cwe": "CWE-918",
        "summary": "A fetch worker sends a user-supplied URL to urllib without a host allowlist.",
        "tags": ["python", "http", "ssrf"],
        "files": {
            "vulnerable/worker.py": """from __future__ import annotations

import urllib.request


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=3) as response:
        return response.read().decode("utf-8")
""",
            "fixed/worker.py": """from __future__ import annotations

import urllib.request
from urllib.parse import urlparse

ALLOWED_HOSTS = {"localhost"}


def fetch(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("unsupported scheme")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("host is not allowed")
    with urllib.request.urlopen(url, timeout=3) as response:
        return response.read().decode("utf-8")
""",
            "benign/worker.py": """from __future__ import annotations

import urllib.request
from urllib.parse import urlparse

ALLOWED_HOSTS = frozenset({"localhost"})


def fetch(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("unsupported scheme")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("host is not allowed")
    request = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(request, timeout=3) as response:
        return response.read().decode("utf-8")
""",
            "mutants/metadata_block.py": """from __future__ import annotations

import urllib.request
from urllib.parse import urlparse

BLOCKED = {"169.254.169.254"}


def fetch(url: str) -> str:
    parsed = urlparse(url)
    if parsed.hostname in BLOCKED:
        raise ValueError("metadata endpoint blocked")
    with urllib.request.urlopen(url, timeout=3) as response:
        return response.read().decode("utf-8")
""",
            "mutants/scheme_only.py": """from __future__ import annotations

import urllib.request
from urllib.parse import urlparse


def fetch(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("unsupported scheme")
    with urllib.request.urlopen(url, timeout=3) as response:
        return response.read().decode("utf-8")
""",
            "poc/exploit.py": """from __future__ import annotations

import http.server
import socketserver
import sys
import threading

from worker import fetch


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"ACV_SSRF_SECRET" if self.path == "/secret" else b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        return


server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
port = server.server_address[1]
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    body = fetch(f"http://127.0.0.1:{port}/secret")
except Exception:
    body = ""
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)

if "ACV_SSRF_SECRET" in body:
    print("exploit: server-side request forgery")
    sys.exit(0)

print("blocked")
sys.exit(1)
""",
            "tests/test_functional.py": """import http.server
import socketserver
import threading

from worker import fetch


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        return


def test_local_fetch() -> None:
    server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert fetch(f"http://localhost:{port}/ok") == "ok"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
""",
        },
        "candidates": [
            candidate("gold", "gold", "fixed/worker.py", True),
            candidate("benign", "benign", "benign/worker.py", True),
            candidate("metadata_block", "mutant", "mutants/metadata_block.py", False),
            candidate("scheme_only", "mutant", "mutants/scheme_only.py", False),
        ],
    },
    {
        "id": "token_signer",
        "title": "Token signer",
        "cwe": "CWE-798",
        "summary": (
            "A signing worker ships a development secret in source "
            "and accepts forged tokens."
        ),
        "tags": ["python", "crypto", "secret"],
        "files": {
            "vulnerable/worker.py": """from __future__ import annotations

import hashlib
import hmac

SECRET = "acv-dev-secret"


def sign(value: str) -> str:
    return hmac.new(SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()


def verify(value: str, signature: str) -> bool:
    return hmac.compare_digest(sign(value), signature)
""",
            "fixed/worker.py": """from __future__ import annotations

import hashlib
import hmac
import os

ENV_KEY = "ACV_TOKEN_SECRET"


def _secret() -> bytes:
    value = os.environ.get(ENV_KEY)
    if not value:
        raise RuntimeError("ACV_TOKEN_SECRET is not set")
    return value.encode()


def sign(value: str) -> str:
    return hmac.new(_secret(), value.encode(), hashlib.sha256).hexdigest()


def verify(value: str, signature: str) -> bool:
    return hmac.compare_digest(sign(value), signature)
""",
            "benign/worker.py": """from __future__ import annotations

import hashlib
import hmac
import os

KEY_NAME = "ACV_TOKEN_SECRET"


def _key() -> bytes:
    raw = os.environ.get(KEY_NAME)
    if raw is None or len(raw) < 16:
        raise RuntimeError("missing or short key")
    return raw.encode()


def sign(value: str) -> str:
    return hmac.new(_key(), value.encode(), hashlib.sha256).hexdigest()


def verify(value: str, signature: str) -> bool:
    return hmac.compare_digest(sign(value), signature)
""",
            "mutants/fallback_literal.py": """from __future__ import annotations

import hashlib
import hmac
import os


def _secret() -> bytes:
    return os.environ.get("ACV_TOKEN_SECRET", "acv-dev-secret").encode()


def sign(value: str) -> str:
    return hmac.new(_secret(), value.encode(), hashlib.sha256).hexdigest()


def verify(value: str, signature: str) -> bool:
    return hmac.compare_digest(sign(value), signature)
""",
            "mutants/module_secret.py": """from __future__ import annotations

import hashlib
import hmac
import os

DEBUG_KEY = "acv-dev-secret"


def _secret() -> bytes:
    return os.environ.get("ACV_TOKEN_SECRET", DEBUG_KEY).encode()


def sign(value: str) -> str:
    return hmac.new(_secret(), value.encode(), hashlib.sha256).hexdigest()


def verify(value: str, signature: str) -> bool:
    return hmac.compare_digest(sign(value), signature)
""",
            "poc/exploit.py": """from __future__ import annotations

import hashlib
import hmac
import os
import sys

os.environ.pop("ACV_TOKEN_SECRET", None)

from worker import verify

KNOWN = "acv-dev-secret"
value = "admin:reset"
signature = hmac.new(KNOWN.encode(), value.encode(), hashlib.sha256).hexdigest()

try:
    ok = verify(value, signature)
except Exception:
    ok = False

if ok:
    print("exploit: forged token accepted")
    sys.exit(0)

print("blocked")
sys.exit(1)
""",
            "tests/test_functional.py": """import os

os.environ["ACV_TOKEN_SECRET"] = "test-secret-value-123456"

from worker import sign, verify


def test_roundtrip() -> None:
    value = "user:42"
    assert verify(value, sign(value))


def test_tamper() -> None:
    value = "user:42"
    assert not verify("user:43", sign(value))
""",
        },
        "candidates": [
            candidate("gold", "gold", "fixed/worker.py", True),
            candidate("benign", "benign", "benign/worker.py", True),
            candidate("fallback_literal", "mutant", "mutants/fallback_literal.py", False),
            candidate("module_secret", "mutant", "mutants/module_secret.py", False),
        ],
    },
    {
        "id": "html_renderer",
        "title": "Comment renderer",
        "cwe": "CWE-79",
        "summary": "A renderer interpolates comment text into HTML without escaping.",
        "tags": ["python", "html", "xss"],
        "files": {
            "vulnerable/worker.py": """from __future__ import annotations


def render_comment(author: str, body: str) -> str:
    return f"<article><h2>{author}</h2><p>{body}</p></article>"
""",
            "fixed/worker.py": """from __future__ import annotations

import html


def render_comment(author: str, body: str) -> str:
    return (
        "<article><h2>"
        + html.escape(author)
        + "</h2><p>"
        + html.escape(body)
        + "</p></article>"
    )
""",
            "benign/worker.py": """from __future__ import annotations

import html


def render_comment(author: str, body: str) -> str:
    return "<article><h2>{}</h2><p>{}</p></article>".format(
        html.escape(author),
        html.escape(body),
    )
""",
            "mutants/script_filter.py": """from __future__ import annotations


def render_comment(author: str, body: str) -> str:
    safe = body.replace("<script>", "").replace("</script>", "")
    return f"<article><h2>{author}</h2><p>{safe}</p></article>"
""",
            "mutants/quote_escape.py": """from __future__ import annotations

import html


def render_comment(author: str, body: str) -> str:
    safe = html.escape(body, quote=True).replace("&lt;", "<").replace("&gt;", ">")
    return f"<article><h2>{author}</h2><p>{safe}</p></article>"
""",
            "poc/exploit.py": """from __future__ import annotations

import sys

from worker import render_comment

payload = '<img src=x onerror="alert(1)">'

try:
    output = render_comment("guest", payload)
except Exception as exc:
    print(f"error: {exc}")
    sys.exit(2)

if "<img" in output and "onerror" in output:
    print("exploit: HTML injection")
    sys.exit(0)

print("blocked")
sys.exit(1)
""",
            "tests/test_functional.py": """from worker import render_comment


def test_plain_comment() -> None:
    output = render_comment("alice", "hello")
    assert "<article>" in output
    assert "alice" in output
    assert "hello" in output


def test_unicode_comment() -> None:
    output = render_comment("Renee", "cafe")
    assert "Renee" in output
    assert "cafe" in output
""",
        },
        "candidates": [
            candidate("gold", "gold", "fixed/worker.py", True),
            candidate("benign", "benign", "benign/worker.py", True),
            candidate("script_filter", "mutant", "mutants/script_filter.py", False),
            candidate("quote_escape", "mutant", "mutants/quote_escape.py", False),
        ],
    },
    {
        "id": "yaml_loader",
        "title": "YAML config loader",
        "cwe": "CWE-94",
        "summary": (
            "A config loader accepts Python object constructors "
            "from an untrusted YAML document."
        ),
        "tags": ["python", "yaml", "deserialization"],
        "files": {
            "vulnerable/worker.py": """from __future__ import annotations

import yaml


def load_config(payload: str) -> dict:
    data = yaml.load(payload, Loader=yaml.Loader)
    if not isinstance(data, dict):
        raise ValueError("config must be a mapping")
    return data
""",
            "fixed/worker.py": """from __future__ import annotations

import yaml


def load_config(payload: str) -> dict:
    data = yaml.safe_load(payload)
    if not isinstance(data, dict):
        raise ValueError("config must be a mapping")
    return data
""",
            "benign/worker.py": """from __future__ import annotations

import yaml


def load_config(payload: str) -> dict:
    data = yaml.load(payload, Loader=yaml.SafeLoader)
    if not isinstance(data, dict):
        raise ValueError("config must be a mapping")
    return data
""",
            "mutants/unsafe_loader.py": """from __future__ import annotations

import yaml


def load_config(payload: str) -> dict:
    data = yaml.load(payload, Loader=yaml.UnsafeLoader)
    if not isinstance(data, dict):
        raise ValueError("config must be a mapping")
    return data
""",
            "mutants/loader_alias.py": """from __future__ import annotations

import yaml


def load_config(payload: str) -> dict:
    data = yaml.load(payload, Loader=yaml.Loader)
    if not isinstance(data, dict):
        raise ValueError("config must be a mapping")
    return data
""",
            "poc/exploit.py": """from __future__ import annotations

import sys
from pathlib import Path

from worker import load_config

MARKER = Path("ACV_YAML_PWNED")
PAYLOAD = "!!python/object/apply:os.system\\n- 'touch ACV_YAML_PWNED'\\n"

try:
    MARKER.unlink(missing_ok=True)
    load_config(PAYLOAD)
except Exception:
    pass

if MARKER.exists():
    MARKER.unlink(missing_ok=True)
    print("exploit: unsafe YAML loader")
    sys.exit(0)

print("blocked")
sys.exit(1)
""",
            "tests/test_functional.py": """from worker import load_config


def test_mapping() -> None:
    assert load_config("name: acv\\nport: 8080\\n") == {"name": "acv", "port": 8080}


def test_invalid() -> None:
    try:
        load_config("- one\\n- two\\n")
    except ValueError:
        return
    raise AssertionError("expected ValueError")
""",
        },
        "candidates": [
            candidate("gold", "gold", "fixed/worker.py", True),
            candidate("benign", "benign", "benign/worker.py", True),
            candidate("unsafe_loader", "mutant", "mutants/unsafe_loader.py", False),
            candidate("loader_alias", "mutant", "mutants/loader_alias.py", False),
        ],
    },
    {
        "id": "token_random",
        "title": "Password reset token",
        "cwe": "CWE-338",
        "summary": "A reset worker uses the predictable random module to build a security token.",
        "tags": ["python", "random", "token"],
        "files": {
            "vulnerable/worker.py": """from __future__ import annotations

import random
import string

ALPHABET = string.ascii_letters + string.digits


def reset_token(length: int = 24) -> str:
    return "".join(random.choices(ALPHABET, k=length))
""",
            "fixed/worker.py": """from __future__ import annotations

import secrets
import string

ALPHABET = string.ascii_letters + string.digits


def reset_token(length: int = 24) -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(length))
""",
            "benign/worker.py": """from __future__ import annotations

import secrets
import string

ALPHABET = string.ascii_letters + string.digits


def reset_token(length: int = 24) -> str:
    generated = []
    for _ in range(length):
        generated.append(secrets.choice(ALPHABET))
    return "".join(generated)
""",
            "mutants/module_seed.py": """from __future__ import annotations

import random
import string

ALPHABET = string.ascii_letters + string.digits
random.seed(1337)


def reset_token(length: int = 24) -> str:
    return "".join(random.choices(ALPHABET, k=length))
""",
            "mutants/time_seed.py": """from __future__ import annotations

import random
import string
import time

ALPHABET = string.ascii_letters + string.digits
random.seed(time.time())


def reset_token(length: int = 24) -> str:
    return "".join(random.choices(ALPHABET, k=length))
""",
            "poc/exploit.py": """from __future__ import annotations

import random
import sys

from worker import reset_token

random.seed(1337)
first = reset_token(16)
random.seed(1337)
second = reset_token(16)

if first == second:
    print("exploit: predictable token")
    sys.exit(0)

print("blocked")
sys.exit(1)
""",
            "tests/test_functional.py": """from worker import reset_token


def test_length() -> None:
    assert len(reset_token(24)) == 24


def test_charset() -> None:
    assert reset_token(24).isalnum()


def test_two_tokens_differ() -> None:
    assert reset_token(24) != reset_token(24)
""",
        },
        "candidates": [
            candidate("gold", "gold", "fixed/worker.py", True),
            candidate("benign", "benign", "benign/worker.py", True),
            candidate("module_seed", "mutant", "mutants/module_seed.py", False),
            candidate("time_seed", "mutant", "mutants/time_seed.py", False),
        ],
    },
    {
        "id": "open_redirect",
        "title": "Post-login redirect",
        "cwe": "CWE-601",
        "summary": "A redirect helper returns the next URL without constraining its host.",
        "tags": ["python", "redirect", "http"],
        "files": {
            "vulnerable/worker.py": """from __future__ import annotations


def next_url(target: str | None) -> str:
    if target:
        return target
    return "/"
""",
            "fixed/worker.py": """from __future__ import annotations

from urllib.parse import urlparse

ALLOWED_HOSTS = {"app.local"}


def next_url(target: str | None) -> str:
    if not target:
        return "/"
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        if parsed.hostname not in ALLOWED_HOSTS:
            return "/"
    return target
""",
            "benign/worker.py": """from __future__ import annotations

from urllib.parse import urlparse

ALLOWED_HOSTS = ("app.local",)


def next_url(target: str | None) -> str:
    if not target:
        return "/"
    parsed = urlparse(target)
    if parsed.hostname and parsed.hostname not in ALLOWED_HOSTS:
        return "/"
    return target
""",
            "mutants/path_prefix.py": """from __future__ import annotations


def next_url(target: str | None) -> str:
    if not target:
        return "/"
    if target.startswith("/") or target.startswith("https://app.local"):
        return target
    return "/"
""",
            "mutants/scheme_only.py": """from __future__ import annotations

from urllib.parse import urlparse


def next_url(target: str | None) -> str:
    if not target:
        return "/"
    parsed = urlparse(target)
    if parsed.scheme and parsed.hostname != "app.local":
        return "/"
    return target
""",
            "poc/exploit.py": """from __future__ import annotations

import sys

from worker import next_url

try:
    target = next_url("//evil.example/login")
except Exception as exc:
    print(f"error: {exc}")
    sys.exit(2)

if target.startswith("//evil.example"):
    print("exploit: open redirect")
    sys.exit(0)

print("blocked")
sys.exit(1)
""",
            "tests/test_functional.py": """from worker import next_url


def test_default() -> None:
    assert next_url(None) == "/"


def test_local_path() -> None:
    assert next_url("/dashboard") == "/dashboard"


def test_allowed_host() -> None:
    assert next_url("https://app.local/home") == "https://app.local/home"
""",
        },
        "candidates": [
            candidate("gold", "gold", "fixed/worker.py", True),
            candidate("benign", "benign", "benign/worker.py", True),
            candidate("path_prefix", "mutant", "mutants/path_prefix.py", False),
            candidate("scheme_only", "mutant", "mutants/scheme_only.py", False),
        ],
    },
]


def write_task(task: dict[str, object]) -> None:
    task_id = str(task["id"])
    root = PACK / task_id
    files = task["files"]
    assert isinstance(files, dict)
    for relative, content in files.items():
        path = root / str(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(content), encoding="utf-8")
    data = root / "data"
    data.mkdir(parents=True, exist_ok=True)
    (data / ".keep").touch()
    manifest = {
        "id": task_id,
        "title": task["title"],
        "cwe": task["cwe"],
        "summary": task["summary"],
        "tags": task["tags"],
        "vulnerable": "vulnerable/worker.py",
        "fixed": "fixed/worker.py",
        "poc": "poc/exploit.py",
        "functional": "tests/test_functional.py",
        "data_dir": "data",
        "candidates": task["candidates"],
    }
    (root / "task.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def seed_sqlite() -> None:
    db = PACK / "sql_lookup" / "data" / "users.db"
    db.parent.mkdir(parents=True, exist_ok=True)
    if db.exists():
        db.unlink()
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE users (username TEXT PRIMARY KEY, role TEXT NOT NULL)")
        conn.executemany(
            "INSERT INTO users (username, role) VALUES (?, ?)",
            [("alice", "admin"), ("bob", "user"), ("carol", "user")],
        )


def main() -> None:
    PACK.mkdir(parents=True, exist_ok=True)
    for task in TASKS:
        write_task(task)
    seed_sqlite()
    print(f"wrote {len(TASKS)} tasks under {PACK}")


if __name__ == "__main__":
    main()
