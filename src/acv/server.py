"""Local research console and verification API.

The server keeps the Groq key on the machine. The browser never sees it. Every
panel in the UI calls the same deterministic runner and checker registry used by
the CLI, so the browser is a view over real execution rather than a static deck.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__
from .checkers import checker_adapters
from .features import feature_flags
from .llm import DEFAULT_MODEL, GroqClient, GroqError
from .manifest import ManifestError, discover_tasks, discover_tasks_multi, find_task, load_task
from .models import ProjectProvenance, ProjectResult, ProjectSpec, SourceResult, TaskSpec
from .projects import (
    ProjectError,
    ProjectLimitError,
    discover_projects,
    discover_projects_multi,
    evaluate_project,
    evaluate_project_candidate,
    evaluate_project_patch,
    find_project,
    project_candidate_files,
    project_catalog,
    project_detail,
    project_file,
    project_run_record,
)
from .repair import RepairError, propose_repair
from .report import build_payload
from .review import (
    ReviewError,
    ReviewRequest,
    ReviewResult,
    find_candidate,
    review_task,
    task_catalog_from_tasks,
)
from .runner import (
    PatchApplyError,
    evaluate_candidate,
    evaluate_patch,
    evaluate_source,
    run_audit_tasks,
)
from .task_import import (
    TaskBundle,
    TaskImportError,
    bundle_from_task,
    import_bundle,
    validate_bundle,
)
from .toolbench import evaluate_checkers

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PACK_ROOT = Path(os.environ.get("ACV_PACK", str(PROJECT_ROOT / "security_workers")))
USER_PACK_ROOT = Path(
    os.environ.get("ACV_USER_PACK", str(PROJECT_ROOT / "user_security_workers"))
)
PACK_ROOTS = [PACK_ROOT, USER_PACK_ROOT]
PROJECT_PACK_ROOT = Path(
    os.environ.get("ACV_PROJECT_PACK", str(PROJECT_ROOT / "project_workers"))
)
USER_PROJECT_PACK_ROOT = Path(
    os.environ.get("ACV_USER_PROJECT_PACK", str(PROJECT_ROOT / "user_project_workers"))
)
PROJECT_PACK_ROOTS = [PROJECT_PACK_ROOT, USER_PROJECT_PACK_ROOT]
PROJECT_RUN_LOG = Path(
    os.environ.get("ACV_PROJECT_RUN_LOG", str(PROJECT_ROOT / "reports" / "project_runs.jsonl"))
)
WEB_ROOT = Path(__file__).resolve().parent / "web"

Checker = Literal["acv-rules", "bandit", "semgrep"]

app = FastAPI(
    title="Autonomous Code Validator",
    version=__version__,
    description=(
        "Deterministic patch verification, checker qualification, and a live model reviewer."
    ),
)


class VerifyRequest(BaseModel):
    """One deterministic gate run."""

    task_id: str = Field(min_length=1)
    candidate: str = Field(min_length=1)
    checker: Checker = "acv-rules"


class VerifyCodeRequest(BaseModel):
    """Run the gate against source supplied by the caller."""

    task_id: str = Field(min_length=1)
    code: str = Field(min_length=1, max_length=200_000)
    checker: Checker = "acv-rules"


class VerifyPatchRequest(BaseModel):
    """Apply a unified diff to the vulnerable worker and run the gate."""

    task_id: str = Field(min_length=1)
    diff: str = Field(min_length=1, max_length=200_000)
    checker: Checker = "acv-rules"


class RepairRequest(BaseModel):
    """Ask the model for a candidate repair, then run the deterministic gate."""

    task_id: str = Field(min_length=1)
    model: str | None = None
    checker: Checker = "acv-rules"


class ProjectVerifyRequest(BaseModel):
    """Verify a generated multi-file overlay, or a named reference candidate."""

    files: dict[str, str] = Field(default_factory=dict)
    candidate: str | None = Field(default=None, max_length=80)
    checker: Checker = "acv-rules"
    provenance: ProjectProvenance = Field(default_factory=ProjectProvenance)
    isolation_acknowledged: bool = False


class ProjectPatchRequest(BaseModel):
    """Apply a multi-file unified diff to a project and run the same gate."""

    diff: str = Field(min_length=1, max_length=2_000_000)
    checker: Checker = "acv-rules"
    provenance: ProjectProvenance = Field(default_factory=ProjectProvenance)
    isolation_acknowledged: bool = False


class QualifyRequest(BaseModel):
    """Optional checker selection for the qualification harness."""

    checkers: list[str] | None = None


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def _task_detail(task: TaskSpec) -> dict[str, object]:
    """Return the real source, exploit, test, and candidates for one task."""

    return {
        "task_id": task.task_id,
        "title": task.title,
        "cwe": task.cwe,
        "summary": task.summary,
        "tags": list(task.tags),
        "paths": {
            "vulnerable": _display_path(task.vulnerable),
            "fixed": _display_path(task.fixed),
            "poc": _display_path(task.poc),
            "functional": _display_path(task.functional),
        },
        "code": {
            "vulnerable": task.vulnerable.read_text(encoding="utf-8"),
            "exploit": task.poc.read_text(encoding="utf-8"),
            "functional": task.functional.read_text(encoding="utf-8"),
        },
        "candidates": [
            {
                "name": candidate.name,
                "kind": candidate.kind,
                "path": _display_path(task.root / candidate.path),
                "expected_security": candidate.expected_security,
                "expected_behavior": candidate.expected_behavior,
                "note": candidate.note,
                "code": (task.root / candidate.path).read_text(encoding="utf-8"),
            }
            for candidate in task.candidates
        ],
    }


def _all_tasks() -> list[TaskSpec]:
    try:
        return discover_tasks_multi(PACK_ROOTS)
    except ManifestError:
        # A malformed user pack must not make the built-in corpus disappear.
        return discover_tasks(PACK_ROOT)


def _load_task(task_id: str) -> TaskSpec:
    return find_task(PACK_ROOTS, task_id)


def _all_projects() -> list[ProjectSpec]:
    try:
        return discover_projects_multi(PROJECT_PACK_ROOTS)
    except ProjectError:
        try:
            return discover_projects(PROJECT_PACK_ROOT)
        except ProjectError:
            return []


def _load_project(project_id: str) -> ProjectSpec:
    return find_project(PROJECT_PACK_ROOTS, project_id)


def _require_safe_project_run(request: ProjectVerifyRequest | ProjectPatchRequest) -> None:
    if request.provenance.criticality == "critical" and not request.isolation_acknowledged:
        raise HTTPException(
            status_code=428,
            detail=(
                "critical code requires isolation_acknowledged=true. The built-in runner "
                "uses process limits only; move this code to a VM or container before "
                "claiming a critical-code result."
            ),
        )


def _project_payload(result: ProjectResult) -> dict[str, object]:
    payload = asdict(result)
    payload["provenance"] = result.provenance.model_dump(mode="json")
    payload["rejected_by"] = result.rejected_by
    return payload


def _log_project_run(result: ProjectResult) -> None:
    if not feature_flags().get("project_run_log", True):
        return
    if not str(PROJECT_RUN_LOG).strip():
        return
    record = project_run_record(result)
    record["logged_at"] = int(time.time())
    try:
        PROJECT_RUN_LOG.parent.mkdir(parents=True, exist_ok=True)
        with PROJECT_RUN_LOG.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        # Logging is observability, not evidence. A read-only checkout must still
        # be able to run the gate.
        return


def _catalog() -> list[dict[str, object]]:
    return task_catalog_from_tasks(_all_tasks())


def _require_feature(name: str) -> None:
    if not feature_flags().get(name, False):
        raise HTTPException(status_code=404, detail=f"feature disabled: {name}")


def _gate_payload(result: SourceResult) -> dict[str, object]:
    payload = asdict(result)
    if not feature_flags().get("patch_preview", True):
        payload["candidate_code"] = ""
        payload["applied_diff"] = ""
    return payload


@app.get("/api", include_in_schema=False)
def api_index() -> dict[str, object]:
    """Small API directory for clients that do not use the UI."""

    return {
        "name": "Autonomous Code Validator",
        "version": __version__,
        "docs": "/docs",
        "endpoints": {
            "health": "GET /api/health",
            "tasks": "GET /api/tasks",
            "task": "GET /api/tasks/{task_id}",
            "verify": "POST /api/verify",
            "verify_code": "POST /api/verify-code",
            "verify_patch": "POST /api/verify-patch",
            "task_template": "GET /api/tasks/template",
            "task_validate": "POST /api/tasks/validate",
            "task_import": "POST /api/tasks/import",
            "tools": "GET /api/tools",
            "qualify": "POST /api/qualify",
            "audit": "POST /api/audit",
            "review": "POST /api/review",
            "repair": "POST /api/repair",
            "projects": "GET /api/projects",
            "project": "GET /api/projects/{project_id}",
            "project_file": "GET /api/projects/{project_id}/file?path=...",
            "project_candidate": "GET /api/projects/{project_id}/candidates/{name}",
            "project_verify": "POST /api/projects/{project_id}/verify",
            "project_verify_patch": "POST /api/projects/{project_id}/verify-patch",
        },
    }


@app.get("/")
def index() -> FileResponse:
    """Serve the interactive research console."""

    return FileResponse(WEB_ROOT / "index.html")


@app.get("/api/health")
def health() -> dict[str, object]:
    """Report whether the live reviewer is configured without exposing the key."""

    try:
        task_count = len(_all_tasks())
    except Exception:
        task_count = 0
    try:
        project_count = len(_all_projects())
    except Exception:
        project_count = 0
    return {
        "ok": True,
        "provider": "groq",
        "model": os.environ.get("ACV_LLM_MODEL", DEFAULT_MODEL),
        "key_configured": GroqClient.is_configured(),
        "tasks": task_count,
        "projects": project_count,
        "version": __version__,
        "ui": WEB_ROOT.is_dir(),
        "features": feature_flags(),
        "pack_roots": [str(PACK_ROOT), str(USER_PACK_ROOT)],
        "project_pack_roots": [str(PROJECT_PACK_ROOT), str(USER_PROJECT_PACK_ROOT)],
        "project_isolation": "process-limits-only",
        "project_run_log": str(PROJECT_RUN_LOG),
    }


@app.get("/api/tasks")
def tasks() -> list[dict[str, object]]:
    """Return the task and candidate catalog used by the UI selectors."""

    try:
        return _catalog()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/tasks/template")
def task_template() -> dict[str, object]:
    """Return an editable bundle based on a known-good built-in task."""

    _require_feature("task_import")
    try:
        builtins = discover_tasks(PACK_ROOT)
    except ManifestError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    task = next(
        (item for item in builtins if item.task_id == "cmd_runner"),
        builtins[0],
    )
    bundle = bundle_from_task(task, task_id="example_cmd_runner")
    return bundle.model_dump(mode="json")


@app.post("/api/tasks/validate")
def task_validate(bundle: TaskBundle) -> dict[str, object]:
    """Validate a task bundle without writing or executing it."""

    _require_feature("task_import")
    try:
        manifest = validate_bundle(bundle)
    except TaskImportError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "task_id": manifest.id,
        "files": sorted(bundle.files),
        "candidates": [candidate.name for candidate in manifest.candidates],
    }


@app.post("/api/tasks/import")
def task_import(bundle: TaskBundle, overwrite: bool = False) -> dict[str, object]:
    """Validate and publish a task bundle into the user pack."""

    _require_feature("task_import")
    try:
        root = import_bundle(bundle, USER_PACK_ROOT, overwrite=overwrite)
        task = load_task(root)
    except TaskImportError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ManifestError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"ok": True, "task": _task_detail(task)}


@app.get("/api/tasks/{task_id}")
def task_detail(task_id: str) -> dict[str, object]:
    """Return the vulnerable source and the complete candidate set for one task."""

    try:
        task = _load_task(task_id)
    except ManifestError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _task_detail(task)


@app.post("/api/verify")
def verify(request: VerifyRequest) -> dict[str, object]:
    """Run the deterministic gate without a model."""

    try:
        task = _load_task(request.task_id)
        candidate = find_candidate(task, request.candidate)
    except (ManifestError, ReviewError) as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    result = evaluate_candidate(task, candidate, primary_checker=request.checker)
    return asdict(result)


@app.post("/api/verify-code")
def verify_code(request: VerifyCodeRequest) -> dict[str, object]:
    """Run the deterministic gate against a caller-supplied replacement module.

    This is intended for local experiments with trusted code. The current runner
    uses a temporary directory, not a hardened sandbox; do not expose this
    endpoint to untrusted remote users.
    """

    try:
        task = _load_task(request.task_id)
    except ManifestError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    result = evaluate_source(task, request.code, primary_checker=request.checker)
    return _gate_payload(result)


@app.post("/api/verify-patch")
def verify_patch(request: VerifyPatchRequest) -> dict[str, object]:
    """Apply a unified diff to the vulnerable worker and run the same gate."""

    try:
        task = _load_task(request.task_id)
    except ManifestError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    try:
        result = evaluate_patch(task, request.diff, primary_checker=request.checker)
    except PatchApplyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _gate_payload(result)


@app.get("/api/projects")
def projects() -> list[dict[str, object]]:
    """List multi-file project tasks and their size profile."""

    _require_feature("project_verification")
    try:
        return project_catalog(_all_projects())
    except ProjectError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/projects/{project_id}")
def project(project_id: str) -> dict[str, object]:
    """Return one project's file inventory, evidence, and limits."""

    _require_feature("project_verification")
    try:
        return project_detail(_load_project(project_id))
    except ProjectError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/projects/{project_id}/file")
def project_file_content(
    project_id: str,
    path: str = Query(min_length=1, max_length=500),
) -> dict[str, object]:
    """Read one file from the project's base tree."""

    _require_feature("project_verification")
    try:
        project_spec = _load_project(project_id)
        return {
            "project_id": project_spec.project_id,
            "path": path,
            "code": project_file(project_spec, path),
        }
    except ProjectError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/projects/{project_id}/candidates/{name}")
def project_candidate(project_id: str, name: str) -> dict[str, object]:
    """Return the overlay files for one reference or mutant candidate."""

    _require_feature("project_verification")
    try:
        project_spec = _load_project(project_id)
        candidate = next(
            (item for item in project_spec.candidates if item.name == name),
            None,
        )
        if candidate is None:
            raise ProjectError(f"unknown project candidate: {name}")
        return {
            "project_id": project_spec.project_id,
            "name": candidate.name,
            "kind": candidate.kind,
            "expected_security": candidate.expected_security,
            "expected_behavior": candidate.expected_behavior,
            "note": candidate.note,
            "files": project_candidate_files(project_spec, name),
        }
    except ProjectError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/projects/{project_id}/verify")
def project_verify(project_id: str, request: ProjectVerifyRequest) -> dict[str, object]:
    """Run the deterministic gate on a generated multi-file overlay."""

    _require_feature("project_verification")
    _require_safe_project_run(request)
    try:
        project_spec = _load_project(project_id)
    except ProjectError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if request.candidate and request.files:
        raise HTTPException(
            status_code=400,
            detail="supply either a named candidate or a files overlay, not both",
        )
    try:
        if request.candidate:
            result = evaluate_project_candidate(
                project_spec,
                request.candidate,
                provenance=request.provenance,
                primary_checker=request.checker,
            )
        else:
            result = evaluate_project(
                project_spec,
                request.files,
                input_mode="overlay" if request.files else "baseline",
                provenance=request.provenance,
                primary_checker=request.checker,
            )
    except ProjectLimitError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except ProjectError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result.isolation_acknowledged = request.isolation_acknowledged
    _log_project_run(result)
    return _project_payload(result)


@app.post("/api/projects/{project_id}/verify-patch")
def project_verify_patch(
    project_id: str,
    request: ProjectPatchRequest,
) -> dict[str, object]:
    """Apply a multi-file diff to a project and run the deterministic gate."""

    _require_feature("project_verification")
    _require_safe_project_run(request)
    try:
        project_spec = _load_project(project_id)
    except ProjectError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    try:
        result = evaluate_project_patch(
            project_spec,
            request.diff,
            provenance=request.provenance,
            primary_checker=request.checker,
        )
    except ProjectLimitError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except ProjectError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result.isolation_acknowledged = request.isolation_acknowledged
    _log_project_run(result)
    return _project_payload(result)


@app.get("/api/tools")
def tools() -> list[dict[str, object]]:
    """List registered checker adapters and their availability."""

    return [
        {
            "name": adapter.name,
            "category": adapter.category,
            "languages": list(adapter.languages),
            "description": adapter.description,
            "available": adapter.available,
            "version": adapter.version,
        }
        for adapter in checker_adapters()
    ]


@app.post("/api/qualify")
def qualify(request: QualifyRequest | None = None) -> dict[str, object]:
    """Run checker qualification on the labeled corpus."""

    names = set(request.checkers) if request and request.checkers else None
    try:
        scores = evaluate_checkers(PACK_ROOT, names, tasks=_all_tasks())
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"scores": [asdict(score) for score in scores]}


@app.post("/api/audit")
def audit() -> dict[str, object]:
    """Run the complete two-sided audit."""

    try:
        results = run_audit_tasks(_all_tasks())
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return build_payload(results)


@app.post("/api/review", response_model=ReviewResult)
def review(request: ReviewRequest) -> ReviewResult:
    """Run one live model review and the deterministic gate."""

    try:
        return review_task(
            _load_task(request.task_id),
            candidate_name=request.candidate,
            model=request.model,
        )
    except ReviewError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except GroqError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/repair")
def repair(request: RepairRequest) -> dict[str, object]:
    """Ask the model for a candidate repair, then gate the generated code."""

    _require_feature("repair")
    try:
        task = _load_task(request.task_id)
    except ManifestError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    try:
        client = GroqClient.from_env(model=request.model)
    except GroqError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    try:
        result = propose_repair(task, client, primary_checker=request.checker)
    except RepairError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except GroqError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return asdict(result)


if WEB_ROOT.is_dir():
    app.mount("/static", StaticFiles(directory=str(WEB_ROOT)), name="static")
