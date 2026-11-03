from __future__ import annotations

from pathlib import Path

from acv.checkers import BuiltinChecker
from acv.manifest import discover_tasks

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "security_workers"


def test_fixed_candidates_are_clean() -> None:
    checker = BuiltinChecker()
    for task in discover_tasks(PACK):
        assert checker.scan(task.fixed) == [], task.task_id


def test_most_vulnerable_candidates_are_flagged() -> None:
    checker = BuiltinChecker()
    flagged = {
        task.task_id: bool(checker.scan(task.vulnerable))
        for task in discover_tasks(PACK)
    }
    assert sum(flagged.values()) >= 9
    assert flagged["cmd_runner"]
    assert flagged["path_reader"]
    assert flagged["url_fetcher"]


def test_sql_rule_flags_direct_interpolation() -> None:
    checker = BuiltinChecker()
    task = next(task for task in discover_tasks(PACK) if task.task_id == "sql_lookup")
    findings = checker.scan(task.root / "mutants" / "string_concat.py")
    assert any(finding.rule_id == "ACV003" for finding in findings)
