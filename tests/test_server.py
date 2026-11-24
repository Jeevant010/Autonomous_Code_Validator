from __future__ import annotations

import difflib

from fastapi.testclient import TestClient

from acv import server
from acv.llm import LLMReview, LLMUsage
from acv.review import DeterministicView, ReviewResult


def _fake_result() -> ReviewResult:
    return ReviewResult(
        task_id="cmd_runner",
        task_title="Shell command runner",
        cwe="CWE-78",
        summary="A worker concatenates input into a shell command.",
        candidate="sh_c_filter",
        candidate_kind="mutant",
        model="test-model",
        latency_ms=12,
        usage=LLMUsage(),
        review=LLMReview(
            verdict="likely_vulnerable",
            confidence=0.9,
            summary="The wrapper still invokes a shell.",
        ),
        deterministic=DeterministicView(
            accepted=True,
            expected_accepted=False,
            correct=False,
            security_pass=True,
            behavior_pass=True,
            checker_pass=True,
            reasons=["accepted known-bad variant"],
            findings=[],
        ),
        llm_matches_gate=False,
        llm_matches_truth=True,
        code_chars=120,
    )


def test_health_endpoint() -> None:
    client = TestClient(server.app)
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["provider"] == "groq"


def test_review_endpoint(monkeypatch) -> None:
    def fake_review(*args: object, **kwargs: object) -> ReviewResult:
        return _fake_result()

    monkeypatch.setattr(server, "review_task", fake_review)
    client = TestClient(server.app)
    response = client.post(
        "/api/review",
        json={"task_id": "cmd_runner", "candidate": "sh_c_filter"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["review"]["verdict"] == "likely_vulnerable"
    assert payload["llm_matches_gate"] is False


def test_root_serves_research_console() -> None:
    client = TestClient(server.app)
    response = client.get("/")
    assert response.status_code == 200
    assert "ACV" in response.text
    assert "Autonomous Code Validator" in response.text
    assert "/static/app.js" in response.text


def test_static_assets_are_mounted() -> None:
    client = TestClient(server.app)
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/styles.css").status_code == 200


def test_task_detail_endpoint() -> None:
    client = TestClient(server.app)
    response = client.get("/api/tasks/cmd_runner")
    assert response.status_code == 200
    payload = response.json()
    assert payload["task_id"] == "cmd_runner"
    assert "shell=True" in payload["code"]["vulnerable"]
    assert len(payload["candidates"]) >= 3
    assert all("code" in candidate for candidate in payload["candidates"])


def test_verify_endpoint_runs_the_gate() -> None:
    client = TestClient(server.app)
    response = client.post(
        "/api/verify",
        json={"task_id": "cmd_runner", "candidate": "gold", "checker": "acv-rules"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["accepted"] is True
    assert payload["correct"] is True
    assert payload["poc_exit"] == 1
    assert payload["behavior_exit"] == 0


def test_verify_code_endpoint_accepts_supplied_source() -> None:
    client = TestClient(server.app)
    detail = client.get("/api/tasks/cmd_runner").json()
    gold = next(candidate for candidate in detail["candidates"] if candidate["name"] == "gold")
    response = client.post(
        "/api/verify-code",
        json={
            "task_id": "cmd_runner",
            "code": gold["code"],
            "checker": "acv-rules",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["accepted"] is True
    assert payload["security_pass"] is True
    assert payload["checker_pass"] is True
    assert payload["elapsed_ms"] >= 0
    assert payload["input_mode"] == "source"
    assert payload["candidate_code"] == gold["code"]
    assert "worker.py" in payload["applied_diff"]


def test_verify_code_endpoint_rejects_still_vulnerable_source() -> None:
    client = TestClient(server.app)
    detail = client.get("/api/tasks/ssrf_redirect").json()
    initial = next(
        candidate for candidate in detail["candidates"] if candidate["name"] == "initial_only"
    )
    response = client.post(
        "/api/verify-code",
        json={
            "task_id": "ssrf_redirect",
            "code": initial["code"],
            "checker": "acv-rules",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["accepted"] is False
    assert payload["security_pass"] is False
    assert payload["behavior_pass"] is True
    assert "PoC still succeeds" in payload["reasons"]


def test_verify_patch_endpoint_applies_a_unified_diff() -> None:
    client = TestClient(server.app)
    detail = client.get("/api/tasks/cmd_runner").json()
    gold = next(candidate for candidate in detail["candidates"] if candidate["name"] == "gold")
    diff = "".join(
        difflib.unified_diff(
            detail["code"]["vulnerable"].splitlines(keepends=True),
            gold["code"].splitlines(keepends=True),
            fromfile="a/worker.py",
            tofile="b/worker.py",
        )
    )
    assert diff
    response = client.post(
        "/api/verify-patch",
        json={"task_id": "cmd_runner", "diff": diff, "checker": "acv-rules"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["diff_applied"] is True
    assert payload["oracle_ok"] is True
    assert payload["accepted"] is True
    assert payload["input_mode"] == "diff"
    assert payload["candidate_code"] == gold["code"]
    assert "worker.py" in payload["applied_diff"]


def test_verify_patch_endpoint_rejects_path_escape() -> None:
    client = TestClient(server.app)
    evil = (
        "--- a/../../etc/passwd\n"
        "+++ b/../../etc/passwd\n"
        "@@ -1 +1 @@\n"
        "-root\n"
        "+pwn\n"
    )
    response = client.post(
        "/api/verify-patch",
        json={"task_id": "cmd_runner", "diff": evil, "checker": "acv-rules"},
    )
    assert response.status_code == 400
    assert "escape" in response.json()["detail"]


def test_tools_endpoint_lists_adapters() -> None:
    client = TestClient(server.app)
    response = client.get("/api/tools")
    assert response.status_code == 200
    names = {tool["name"] for tool in response.json()}
    assert {"acv-rules", "bandit", "semgrep"} <= names


def test_qualify_endpoint_can_run_one_checker() -> None:
    client = TestClient(server.app)
    response = client.post("/api/qualify", json={"checkers": ["acv-rules"]})
    assert response.status_code == 200
    scores = response.json()["scores"]
    assert len(scores) == 1
    assert scores[0]["tool"] == "acv-rules"
    assert scores[0]["samples"] > 0


def test_audit_endpoint(monkeypatch) -> None:
    monkeypatch.setattr(server, "run_audit_tasks", lambda _tasks: [])
    client = TestClient(server.app)
    response = client.post("/api/audit")
    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["tasks"] == 0
    assert payload["tasks"] == []
