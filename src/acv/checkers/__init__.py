"""Checker adapters.

The verifier treats every checker the same way: it consumes a candidate file and
returns normalized findings. Checkers are registered in ``registry`` so the
qualification harness can compare their detection quality.
"""

from .bandit_adapter import run_bandit
from .builtin import BuiltinChecker
from .registry import (
    CheckerAdapter,
    CheckerCategory,
    checker_adapters,
    get_adapter,
    run_builtin,
    select_adapters,
)
from .semgrep_adapter import run_semgrep

__all__ = [
    "BuiltinChecker",
    "CheckerAdapter",
    "CheckerCategory",
    "checker_adapters",
    "get_adapter",
    "run_bandit",
    "run_builtin",
    "run_semgrep",
    "select_adapters",
]
