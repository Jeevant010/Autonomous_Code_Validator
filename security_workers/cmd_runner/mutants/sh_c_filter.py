from __future__ import annotations

import subprocess


def run_echo(value: str) -> str:
    cleaned = value.replace(";", "")
    completed = subprocess.run(["sh", "-c", "echo " + cleaned], capture_output=True, text=True)
    return completed.stdout
