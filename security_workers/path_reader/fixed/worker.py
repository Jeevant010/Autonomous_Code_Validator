from __future__ import annotations

import os
from pathlib import Path

BASE = (Path(os.environ["ACV_DATA_DIR"]) / "sandbox").resolve()


def read_note(name: str) -> str:
    target = (BASE / name).resolve()
    if not target.is_relative_to(BASE):
        raise ValueError("path escapes sandbox")
    return target.read_text(encoding="utf-8")
