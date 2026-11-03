from __future__ import annotations

import subprocess


def run_echo(value: str) -> str:
    process = subprocess.Popen(["echo", value], stdout=subprocess.PIPE, text=True)
    output, _ = process.communicate(timeout=5)
    return output
