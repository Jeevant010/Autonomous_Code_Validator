from __future__ import annotations

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
