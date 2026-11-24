from __future__ import annotations

import difflib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from acv.projects import (
    ProjectError,
    ProjectLimitError,
    evaluate_project,
    evaluate_project_candidate,
    evaluate_project_patch,
    load_candidate_overlay,
    load_project,
    materialize,
    run_project_checkers,
    validate_overlay,
)
from acv.server import app

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACK = PROJECT_ROOT / "project_workers"


@pytest.fixture(scope="module")
def project():
    return load_project(PACK / "doc_portal")


@pytest.fixture(scope="module")
def real_project():
    return load_project(PACK / "gitpython_cve_2022_24439")


def test_project_has_real_multi_file_scale(project) -> None:
    assert project.project_id == "doc_portal"
    assert project.vulnerable.is_dir()
    assert project.poc.is_file()
    assert project.functional.is_file()
    assert len(project.candidates) == 3


def test_gold_and_benign_are_accepted(project) -> None:
    for name in ("gold", "benign"):
        result = evaluate_project_candidate(project, name)
        assert result.accepted, (name, result.reasons)
        assert result.security_pass
        assert result.behavior_pass
        assert result.checker_pass
        assert result.total_files >= 15
        assert result.total_lines >= 500


def test_incomplete_fix_is_rejected(project) -> None:
    result = evaluate_project_candidate(project, "absolute_only")
    assert not result.accepted
    assert result.security_pass is False
    assert result.behavior_pass is True
    assert "PoC still succeeds" in result.reasons


def test_vulnerable_baseline_is_rejected(project) -> None:
    result = evaluate_project(project, {}, input_mode="baseline")
    assert not result.accepted
    assert result.security_pass is False
    assert result.checker_pass is False
    assert any(finding.path == "portal/paths.py" for finding in result.findings)


def test_checker_scope_covers_project_sources(project) -> None:
    with materialize(project, {}) as workdir:
        results = run_project_checkers(project, workdir)
    primary = results["acv-rules"]
    assert primary.files_scanned >= 15
    assert any(finding.path == "portal/paths.py" for finding in primary.findings)


def test_overlay_path_escape_is_rejected(project) -> None:
    with pytest.raises(ProjectError):
        validate_overlay({"../outside.py": "print('no')\n"}, project)
    with pytest.raises(ProjectError):
        validate_overlay({"/etc/passwd": "no\n"}, project)


def test_overlay_may_not_replace_the_harness(project) -> None:
    with pytest.raises(ProjectError):
        validate_overlay({"conftest.py": "print('no')\n"}, project)
    with pytest.raises(ProjectError):
        validate_overlay({"portal/../conftest.py": "print('no')\n"}, project)


def test_overlay_count_limit(project) -> None:
    files = {f"generated/module_{index}.py": "VALUE = 1\n" for index in range(251)}
    with pytest.raises(ProjectLimitError):
        validate_overlay(files, project)


def test_gold_overlay_can_be_supplied_by_a_generator(project) -> None:
    overlay = load_candidate_overlay(project, "gold")
    result = evaluate_project(project, overlay, input_mode="overlay")
    assert result.accepted
    assert result.overlay_files == ["portal/paths.py"]


def test_unscannable_generated_file_blocks_acceptance(project) -> None:
    overlay = load_candidate_overlay(project, "gold")
    overlay["portal/generated/broken.py"] = "def broken(:\n"
    result = evaluate_project(project, overlay, input_mode="overlay")
    assert not result.accepted
    assert result.behavior_pass is True
    assert result.checker_pass is False
    assert any(
        not score.coverage_complete for score in result.checker_results.values()
    )
    assert any("coverage is incomplete" in reason for reason in result.reasons)


def test_large_generated_overlay_is_judged(project) -> None:
    overlay = load_candidate_overlay(project, "gold")
    for index in range(20):
        lines = [f"VALUE_{index}_{line} = {line}" for line in range(20)]
        overlay[f"portal/generated/module_{index}.py"] = "\n".join(lines) + "\n"
    result = evaluate_project(project, overlay, input_mode="overlay")
    assert result.accepted, result.reasons
    assert result.total_files >= 38
    assert result.total_lines >= 1300
    assert len(result.overlay_files) == 21


def test_multi_file_diff_is_gated(project) -> None:
    before = (project.vulnerable / "portal/paths.py").read_text(encoding="utf-8")
    after = (project.root / "fixed" / "portal" / "paths.py").read_text(encoding="utf-8")
    diff = "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile="a/portal/paths.py",
            tofile="b/portal/paths.py",
        )
    )
    result = evaluate_project_patch(project, diff)
    assert result.accepted, result.reasons
    assert result.diff_applied
    assert result.overlay_files == ["portal/paths.py"]


def test_real_repo_case_gold_and_benign_are_accepted(real_project) -> None:
    for name in ("gold", "benign"):
        result = evaluate_project_candidate(real_project, name)
        assert result.accepted, (name, result.reasons)
        assert result.security_pass
        assert result.behavior_pass
        assert result.checker_pass
        assert result.total_files >= 70
        assert result.total_lines >= 20_000


def test_real_repo_incomplete_fix_is_rejected_by_the_second_path(real_project) -> None:
    result = evaluate_project_candidate(real_project, "clone_only")
    assert not result.accepted
    assert result.security_pass is False
    assert result.behavior_pass is True
    assert result.checker_pass is True
    assert "PoC still succeeds" in result.reasons
    assert "remote_fetch=True" in result.poc_output


def test_real_repo_vulnerable_baseline_is_rejected(real_project) -> None:
    result = evaluate_project(real_project, {}, input_mode="baseline")
    assert not result.accepted
    assert result.security_pass is False
    assert result.checker_pass is True


def test_project_api_catalog_and_file() -> None:
    client = TestClient(app)
    catalog = client.get("/api/projects")
    assert catalog.status_code == 200
    ids = {item["project_id"] for item in catalog.json()}
    assert "doc_portal" in ids
    assert "gitpython_cve_2022_24439" in ids

    detail = client.get("/api/projects/doc_portal")
    assert detail.status_code == 200
    body = detail.json()
    assert body["total_files"] >= 15
    assert body["isolation"]
    assert len(body["checker_scope"]) >= 15

    source = client.get(
        "/api/projects/doc_portal/file",
        params={"path": "portal/paths.py"},
    )
    assert source.status_code == 200
    assert "resolve_document" in source.json()["code"]

    escaped = client.get(
        "/api/projects/doc_portal/file",
        params={"path": "../task.json"},
    )
    assert escaped.status_code == 404


def test_project_api_verify_named_candidate() -> None:
    client = TestClient(app)
    response = client.post(
        "/api/projects/doc_portal/verify",
        json={"candidate": "gold", "checker": "acv-rules"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] is True
    assert body["rejected_by"] == "none"
    assert body["isolation"] == "process-limits-only"
    assert body["provenance"]["model"] == ""


def test_project_api_accepts_model_provenance_and_generated_files() -> None:
    project = load_project(PACK / "doc_portal")
    overlay = load_candidate_overlay(project, "gold")
    client = TestClient(app)
    response = client.post(
        "/api/projects/doc_portal/verify",
        json={
            "files": overlay,
            "provenance": {
                "model": "local-coder-32b",
                "provider": "vllm",
                "backend": "local GPU",
                "quantization": "AWQ",
                "temperature": 0,
                "seed": 7,
                "criticality": "standard",
            },
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] is True
    assert body["provenance"]["model"] == "local-coder-32b"
    assert body["provenance"]["quantization"] == "AWQ"
    assert body["input_mode"] == "overlay"


def test_project_api_requires_ack_for_critical_code() -> None:
    client = TestClient(app)
    response = client.post(
        "/api/projects/doc_portal/verify",
        json={
            "candidate": "gold",
            "provenance": {"model": "local-studio", "criticality": "critical"},
        },
    )
    assert response.status_code == 428
    assert "isolation_acknowledged" in response.json()["detail"]


def test_critical_run_records_acknowledgement() -> None:
    client = TestClient(app)
    response = client.post(
        "/api/projects/doc_portal/verify",
        json={
            "candidate": "gold",
            "provenance": {"criticality": "critical", "model": "critical-test"},
            "isolation_acknowledged": True,
        },
    )
    assert response.status_code == 200
    assert response.json()["isolation_acknowledged"] is True


def test_project_api_rejects_harness_overlay() -> None:
    client = TestClient(app)
    response = client.post(
        "/api/projects/doc_portal/verify",
        json={"files": {"conftest.py": "raise SystemExit(0)\n"}},
    )
    assert response.status_code == 400
