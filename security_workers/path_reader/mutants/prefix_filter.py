from __future__ import annotations

import os
from pathlib import Path

BASE = Path(os.environ["ACV_DATA_DIR"]) / "sandbox"


def read_note(name: str) -> str:
    if name.startswith(".."):
        raise ValueError("blocked")
    return (BASE / name).read_text(encoding="utf-8")
