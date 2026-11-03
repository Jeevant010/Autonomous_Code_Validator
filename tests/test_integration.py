from __future__ import annotations

import json
from pathlib import Path

from acv.manifest import load_task
from acv.report import build_payload
from acv.runner import run_task

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "security_workers"


def test_cmd_runner_end_to_end() -> None:
    result = run_task(load_task(PACK / "cmd_runner"))
    assert result.baseline_ok
    by_name = {candidate.name: candidate for candidate in result.candidates}
    assert by_name["gold"].accepted
    assert by_name["benign"].accepted
    assert not by_name["semicolon_filter"].accepted
    assert by_name["semicolon_filter"].rejected_by == "checker"
    # A known residual risk: the wrapper is not modeled by the rule pack.
    assert by_name["sh_c_filter"].accepted


def test_sql_benign_is_a_measured_false_rejection() -> None:
    result = run_task(load_task(PACK / "sql_lookup"))
    assert result.baseline_ok
    benign = next(candidate for candidate in result.candidates if candidate.kind == "benign")
    assert benign.security_pass
    assert benign.behavior_pass
    assert not benign.checker_pass
    assert not benign.accepted


def test_payload_is_serializable() -> None:
    result = run_task(load_task(PACK / "cmd_runner"))
    payload = build_payload([result])
    assert payload["summary"]["tasks"] == 1
    assert payload["summary"]["candidates"] == 4
    assert payload["summary"]["false_passes"] == 1
    encoded = json.dumps(payload)
    assert "cmd_runner" in encoded
