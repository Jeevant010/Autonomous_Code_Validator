from __future__ import annotations

import json

from fastapi.testclient import TestClient

from acv import server
from acv.llm import LLMCompletion, LLMUsage
from acv.manifest import load_task
from acv.repair import propose_repair


def test_task_template_and_validation() -> None:
    client = TestClient(server.app)
    template = client.get("/api/tasks/template")
    assert template.status_code == 200
    bundle = template.json()
    assert bundle["manifest"]["id"] == "example_cmd_runner"
    assert "vulnerable/worker.py" in bundle["files"]
    assert "poc/exploit.py" in bundle["files"]

    response = client.post("/api/tasks/validate", json=bundle)
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["task_id"] == "example_cmd_runner"
    assert "vulnerable/worker.py" in payload["files"]


def test_task_import_writes_to_user_pack(monkeypatch, tmp_path) -> None:
    user_pack = tmp_path / "user_security_workers"
    monkeypatch.setattr(server, "USER_PACK_ROOT", user_pack)
    monkeypatch.setattr(server, "PACK_ROOTS", [server.PACK_ROOT, user_pack])

    client = TestClient(server.app)
    bundle = client.get("/api/tasks/template").json()
    bundle["manifest"]["id"] = "example_import"
    bundle["manifest"]["title"] = "Example imported command runner"

    response = client.post("/api/tasks/import", json=bundle)
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["task"]["task_id"] == "example_import"
    assert (user_pack / "example_import" / "task.json").exists()
    assert load_task(user_pack / "example_import").task_id == "example_import"

    detail = client.get("/api/tasks/example_import")
    assert detail.status_code == 200
    assert detail.json()["task_id"] == "example_import"

    catalog = client.get("/api/tasks").json()
    assert any(task["task_id"] == "example_import" for task in catalog)


def test_task_import_rejects_missing_file(monkeypatch, tmp_path) -> None:
    user_pack = tmp_path / "user_security_workers"
    monkeypatch.setattr(server, "USER_PACK_ROOT", user_pack)
    monkeypatch.setattr(server, "PACK_ROOTS", [server.PACK_ROOT, user_pack])

    client = TestClient(server.app)
    bundle = client.get("/api/tasks/template").json()
    bundle["manifest"]["id"] = "example_missing"
    del bundle["files"]["poc/exploit.py"]

    response = client.post("/api/tasks/validate", json=bundle)
    assert response.status_code == 400
    assert "missing required files" in response.json()["detail"]


class FakeRepairClient:
    def __init__(self, code: str) -> None:
        self.code = code
        self.calls = 0

    def complete_json(self, system_prompt: str, user_prompt: str) -> LLMCompletion:
        self.calls += 1
        assert "untrusted data" in system_prompt.lower()
        assert "VULNERABLE IMPLEMENTATION" in user_prompt
        return LLMCompletion(
            data={
                "summary": "Use the fixed argument list.",
                "code": self.code,
                "confidence": 0.8,
                "assumptions": ["the caller only passes text"],
                "test_gaps": ["no shell metacharacter test"],
            },
            model="fake-model",
            latency_ms=3,
            usage=LLMUsage(prompt_tokens=10, completion_tokens=20, total_tokens=30),
        )


def test_repair_proposal_is_gated() -> None:
    task = load_task(server.PACK_ROOT / "cmd_runner")
    fixed = task.fixed.read_text(encoding="utf-8")
    client = FakeRepairClient(fixed)
    result = propose_repair(task, client)
    assert client.calls == 1
    assert result.model == "fake-model"
    assert result.proposal.confidence == 0.8
    assert result.gate.accepted is True
    assert result.gate.input_mode == "source"
    assert result.gate.candidate_code == fixed.strip()


def test_repair_endpoint_returns_proposal_and_gate(monkeypatch) -> None:
    task = load_task(server.PACK_ROOT / "cmd_runner")
    fixed = task.fixed.read_text(encoding="utf-8")
    monkeypatch.setattr(
        server.GroqClient,
        "from_env",
        classmethod(lambda cls, model=None: FakeRepairClient(fixed)),
    )
    client = TestClient(server.app)
    response = client.post("/api/repair", json={"task_id": "cmd_runner"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["task_id"] == "cmd_runner"
    assert payload["proposal"]["summary"] == "Use the fixed argument list."
    assert payload["gate"]["accepted"] is True
    assert payload["usage"]["total_tokens"] == 30


def test_repair_endpoint_rejects_invalid_model_output(monkeypatch) -> None:
    class BadClient:
        def complete_json(self, system_prompt: str, user_prompt: str) -> LLMCompletion:
            return LLMCompletion(
                data={"summary": "missing code"},
                model="fake-model",
                latency_ms=1,
                usage=LLMUsage(),
            )

    monkeypatch.setattr(
        server.GroqClient,
        "from_env",
        classmethod(lambda cls, model=None: BadClient()),
    )
    client = TestClient(server.app)
    response = client.post("/api/repair", json={"task_id": "cmd_runner"})
    assert response.status_code == 502
    assert "invalid repair proposal" in response.json()["detail"]


def test_feature_flags_are_reported() -> None:
    client = TestClient(server.app)
    payload = client.get("/api/health").json()
    assert set(payload["features"]) == {
        "guided_workflow",
        "patch_preview",
        "task_import",
        "repair",
        "project_verification",
        "project_run_log",
    }
    assert json.dumps(payload["features"])


def test_project_feature_can_be_disabled(monkeypatch) -> None:
    monkeypatch.setenv("ACV_FEATURE_PROJECTS", "0")
    client = TestClient(server.app)
    assert client.get("/api/projects").status_code == 404
    assert client.get("/api/health").json()["features"]["project_verification"] is False


def test_patch_preview_can_be_disabled(monkeypatch) -> None:
    monkeypatch.setenv("ACV_FEATURE_PATCH_PREVIEW", "0")
    client = TestClient(server.app)
    detail = client.get("/api/tasks/cmd_runner").json()
    gold = next(candidate for candidate in detail["candidates"] if candidate["name"] == "gold")
    response = client.post(
        "/api/verify-code",
        json={"task_id": "cmd_runner", "code": gold["code"], "checker": "acv-rules"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["accepted"] is True
    assert payload["candidate_code"] == ""
    assert payload["applied_diff"] == ""
