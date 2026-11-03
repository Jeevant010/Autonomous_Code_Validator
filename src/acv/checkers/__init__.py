"""Checker adapters.

The verifier treats every checker the same way: it consumes a candidate file and
returns normalized findings. The built-in rule pack is deterministic and works
offline. Bandit is an optional comparison point that is installed with the
project because it is small and useful.
"""

from .bandit_adapter import run_bandit
from .builtin import BuiltinChecker

__all__ = ["BuiltinChecker", "run_bandit"]
