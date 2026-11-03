from __future__ import annotations

import os
from pathlib import Path

BASE = Path(os.environ["ACV_DATA_DIR"]) / "sandbox"


def read_note(name: str) -> str:
    target = Path(os.path.normpath(BASE / name))
    return target.read_text(encoding="utf-8")
