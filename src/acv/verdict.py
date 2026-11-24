"""Structured verdicts for executable evidence.

The PoC exit-code contract alone cannot tell "the attack was blocked" apart
from "the candidate crashed before the attack ran", because Python exits 1 for
both. Without this module a candidate whose module raises ``ImportError`` is
scored as a successful repair: the single most damaging false pass a security
gate can produce.
"""

from __future__ import annotations

from typing import Literal

PocVerdict = Literal["vulnerable", "blocked", "error"]

_TRACEBACK = "Traceback (most recent call last)"


def classify_poc(exit_code: int, output: str) -> PocVerdict:
    """Map a PoC exit code and its output onto a three-way verdict.

    ``vulnerable`` means the attack reproduced (exit 0). ``blocked`` means the
    PoC ran to completion and refused to fire (exit 1, no traceback). ``error``
    means no trustworthy verdict exists: the fixture broke (exit 2), the process
    was killed or timed out, or the candidate crashed with a traceback.
    """

    if exit_code == 0:
        return "vulnerable"
    if exit_code == 2:
        return "error"
    if exit_code == 1:
        return "error" if _TRACEBACK in output else "blocked"
    return "error"
