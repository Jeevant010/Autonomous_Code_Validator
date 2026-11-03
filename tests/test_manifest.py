from __future__ import annotations

import json
from pathlib import Path

import pytest

from acv.manifest import ManifestError, discover_tasks, load_task

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "security_workers"


def test_pack_has_ten_tasks() -> None:
    tasks = discover_tasks(PACK)
    assert len(tasks) == 10
    assert len({task.task_id for task in tasks}) == 10
    assert all(len(task.candidates) == 4 for task in tasks)


def test_each_task_has_a_gold_safe_and_bad_variant() -> None:
    for task in discover_tasks(PACK):
        kinds = {candidate.kind for candidate in task.candidates}
        assert {"gold", "benign", "mutant"} <= kinds
        assert task.poc.exists()
        assert task.functional.exists()
        assert task.data_dir.is_dir()


def test_invalid_manifest_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "broken"
    root.mkdir()
    (root / "data").mkdir()
    (root / "worker.py").write_text("def run() -> None:\n    return None\n", encoding="utf-8")
    (root / "poc.py").write_text("raise SystemExit(1)\n", encoding="utf-8")
    (root / "test_worker.py").write_text(
        "def test_ok() -> None:\n    assert True\n", encoding="utf-8"
    )
    manifest = {
        "id": "broken",
        "title": "Broken task",
        "cwe": "CWE-000",
        "summary": "This task has no candidates.",
        "vulnerable": "worker.py",
        "fixed": "worker.py",
        "poc": "poc.py",
        "functional": "test_worker.py",
        "data_dir": "data",
        "candidates": [],
    }
    (root / "task.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ManifestError):
        load_task(root)
