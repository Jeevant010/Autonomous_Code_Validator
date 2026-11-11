"""Checker adapter registry.

Every checker is exposed through the same small interface. This is what makes
tool qualification possible: the benchmark does not need to know whether a
checker is a local AST rule pack, Bandit, Semgrep, or another subprocess.
"""

from __future__ import annotations

import importlib.util
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Literal

from ..models import CheckerResult
from .bandit_adapter import run_bandit
from .builtin import BuiltinChecker
from .semgrep_adapter import run_semgrep

CheckerCategory = Literal["sast", "secrets", "dependencies", "iac", "container", "dast"]


@dataclass(frozen=True)
class CheckerAdapter:
    """One checker that can be compared with the others."""

    name: str
    category: CheckerCategory
    languages: tuple[str, ...]
    description: str
    run: Callable[[Path], CheckerResult]
    available: bool = True
    version: str | None = None


def _bandit_version() -> str | None:
    try:
        return version("bandit")
    except PackageNotFoundError:
        return None


def _bandit_available() -> bool:
    return importlib.util.find_spec("bandit") is not None or shutil.which("bandit") is not None


def _semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def run_builtin(path: Path) -> CheckerResult:
    """Run the offline rule pack through the common adapter interface."""

    checker = BuiltinChecker()
    return CheckerResult(
        tool=checker.tool,
        available=True,
        findings=checker.scan(path),
        version=checker.version,
    )


ADAPTERS: tuple[CheckerAdapter, ...] = (
    CheckerAdapter(
        name="acv-rules",
        category="sast",
        languages=("python",),
        description="Offline deterministic AST/regex rule pack",
        run=run_builtin,
        available=True,
        version=BuiltinChecker.version,
    ),
    CheckerAdapter(
        name="bandit",
        category="sast",
        languages=("python",),
        description="Bandit Python security analyzer",
        run=run_bandit,
        available=_bandit_available(),
        version=_bandit_version(),
    ),
    CheckerAdapter(
        name="semgrep",
        category="sast",
        languages=("python", "javascript", "typescript", "go", "java"),
        description="Semgrep rule-based SAST (optional)",
        run=run_semgrep,
        available=_semgrep_available(),
    ),
)


def checker_adapters() -> tuple[CheckerAdapter, ...]:
    """Return every registered checker."""

    return ADAPTERS


def get_adapter(name: str) -> CheckerAdapter:
    """Return one adapter by name."""

    for adapter in ADAPTERS:
        if adapter.name == name:
            return adapter
    raise KeyError(f"unknown checker: {name}")


def select_adapters(names: set[str] | None = None) -> tuple[CheckerAdapter, ...]:
    """Return the requested adapters, or every adapter when names is empty."""

    if not names:
        return ADAPTERS
    return tuple(get_adapter(name) for name in sorted(names))
