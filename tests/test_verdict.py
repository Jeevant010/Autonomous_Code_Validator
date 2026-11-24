"""Regression tests for the PoC verdict contract.

The gate used to treat any exit 1 as "attack blocked". Python also exits 1 for
an unhandled exception, so a candidate that could not even be imported was
scored as a successful security repair. These tests pin the three-way verdict
and the end-to-end behaviour that depends on it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from acv.manifest import discover_tasks
from acv.projects import discover_projects
from acv.runner import run_poc
from acv.verdict import classify_poc


class TestClassifyPoc:
    def test_exit_zero_is_vulnerable(self) -> None:
        assert classify_poc(0, "exploit: command injection") == "vulnerable"

    def test_exit_two_is_error(self) -> None:
        assert classify_poc(2, "error: fixture broken") == "error"

    def test_clean_exit_one_is_blocked(self) -> None:
        assert classify_poc(1, "blocked") == "blocked"

    def test_traceback_exit_one_is_error(self) -> None:
        output = (
            "Traceback (most recent call last):\n"
            '  File "poc/exploit.py", line 6, in <module>\n'
            "    from worker import run_echo\n"
            "ModuleNotFoundError: No module named 'nope'\n"
        )
        assert classify_poc(1, output) == "error"

    @pytest.mark.parametrize("code", [124, 126, 128 + 9, 137])
    def test_timeouts_and_signals_are_errors(self, code: int) -> None:
        assert classify_poc(code, "") == "error"


class TestCrashIsNotAFix:
    """A candidate that cannot be imported must never count as repaired."""

    @pytest.fixture(scope="class")
    def cmd_runner(self):
        tasks = discover_tasks(Path("security_workers"))
        return next(task for task in tasks if task.task_id == "cmd_runner")

    def test_unimportable_candidate_is_an_error(self, cmd_runner, tmp_path: Path) -> None:
        candidate = tmp_path / "worker.py"
        candidate.write_text(
            "import this_module_does_not_exist_at_all\n\n"
            "def run_echo(value):\n"
            "    return value\n",
            encoding="utf-8",
        )

        exit_code, output = run_poc(cmd_runner, candidate)

        assert exit_code == 1, "an import failure still exits 1; that is the trap"
        assert classify_poc(exit_code, output) == "error"

    def test_reference_fix_is_still_blocked(self, cmd_runner) -> None:
        fixed = cmd_runner.root / "fixed" / "worker.py"

        exit_code, output = run_poc(cmd_runner, fixed)

        assert classify_poc(exit_code, output) == "blocked"


class TestRealRepositoryGate:
    """The GitPython CVE fixture is a real 22k-line package, not a toy."""

    def test_project_pack_contains_the_real_cve(self) -> None:
        ids = {project.project_id for project in discover_projects(Path("project_workers"))}
        assert "gitpython_cve_2022_24439" in ids
