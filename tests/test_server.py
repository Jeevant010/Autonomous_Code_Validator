from __future__ import annotations

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

    monkeypatch.setattr(server, "review_by_id", fake_review)
    client = TestClient(server.app)
    response = client.post(
        "/api/review",
        json={"task_id": "cmd_runner", "candidate": "sh_c_filter"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["review"]["verdict"] == "likely_vulnerable"
    assert payload["llm_matches_gate"] is False
