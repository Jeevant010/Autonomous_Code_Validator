from __future__ import annotations

import subprocess


def run_echo(value: str) -> str:
    completed = subprocess.run(
        ["echo", value],
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.stdout
