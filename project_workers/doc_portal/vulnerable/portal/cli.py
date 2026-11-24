"""Command-line entry point for the document portal."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import Settings
from .errors import PortalError
from .service import DocumentService


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="doc-portal")
    parser.add_argument("--root", type=Path, default=Path("."), help="document root")
    parser.add_argument("--read-only", action="store_true", help="disable writes")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list documents")
    read = sub.add_parser("read", help="read a document")
    read.add_argument("name")
    search = sub.add_parser("search", help="search document text")
    search.add_argument("query")
    write = sub.add_parser("write", help="write a document from stdin")
    write.add_argument("name")
    delete = sub.add_parser("delete", help="delete a document")
    delete.add_argument("name")
    stats = sub.add_parser("stats", help="print aggregate statistics")
    return parser


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = Settings(root=args.root, read_only=args.read_only)
    service = DocumentService(settings)
    try:
        if args.command == "list":
            for item in service.list():
                print(f"{item.size:>9}  {item.name}")
            return 0
        if args.command == "read":
            sys.stdout.write(service.read(args.name).text)
            return 0
        if args.command == "search":
            for hit in service.search(args.query):
                print(f"{hit.score:>4}  {hit.name}  {hit.snippet}")
            return 0
        if args.command == "write":
            text = sys.stdin.read()
            document = service.write(args.name, text)
            print(json.dumps({"name": document.name, "size": document.size}))
            return 0
        if args.command == "delete":
            service.delete(args.name)
            return 0
        if args.command == "stats":
            print(json.dumps(service.stats().__dict__, sort_keys=True))
            return 0
    except PortalError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 2


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
