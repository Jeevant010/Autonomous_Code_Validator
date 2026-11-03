from __future__ import annotations

import os

BASE = os.path.realpath(os.path.join(os.environ["ACV_DATA_DIR"], "sandbox"))


def read_note(name: str) -> str:
    target = os.path.realpath(os.path.join(BASE, name))
    if os.path.commonpath([BASE, target]) != BASE:
        raise ValueError("path escapes sandbox")
    with open(target, encoding="utf-8") as handle:
        return handle.read()
