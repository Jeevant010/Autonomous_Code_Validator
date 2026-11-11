from __future__ import annotations

from pathlib import Path

from acv.manifest import discover_tasks
from acv.toolbench import build_samples, evaluate_checkers

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "security_workers"


def test_samples_cover_vulnerable_and_safe_files() -> None:
    tasks = discover_tasks(PACK)
    samples = build_samples(PACK)

    assert len(samples) == len(tasks) * 5
    assert sum(1 for sample in samples if sample.expected_vulnerable) == len(tasks) * 3
    assert sum(1 for sample in samples if not sample.expected_vulnerable) == len(tasks) * 2


def test_builtin_checker_is_scored() -> None:
    samples = build_samples(PACK)
    scores = evaluate_checkers(PACK, {"acv-rules"})

    assert len(scores) == 1
    score = scores[0]
    assert score.available
    assert score.samples == len(samples)
    assert score.tp + score.fn == 33
    assert score.fp + score.tn == 22
    assert 0.0 <= score.precision <= 1.0
    assert 0.0 <= score.recall <= 1.0
    assert score.cwe


def test_unknown_checker_is_rejected() -> None:
    try:
        evaluate_checkers(PACK, {"does-not-exist"})
    except KeyError as exc:
        assert "unknown checker" in str(exc)
    else:
        raise AssertionError("unknown checker should fail")
