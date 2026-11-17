"""Local research console and verification API.

The server keeps the Groq key on the machine. The browser never sees it. Every
panel in the UI calls the same deterministic runner and checker registry used by
the CLI, so the browser is a view over real execution rather than a static deck.
"""

from __future__ import annotations

import os
from dataclasses import asdict
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__
from .checkers import checker_adapters
from .llm import DEFAULT_MODEL, GroqClient, GroqError
from .manifest import ManifestError, load_task
from .models import TaskSpec
from .report import build_payload
from .review import (
    ReviewError,
    ReviewRequest,
    ReviewResult,
    find_candidate,
    review_by_id,
    task_catalog,
)
from .runner import evaluate_candidate, evaluate_source, run_audit
from .toolbench import evaluate_checkers

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PACK_ROOT = Path(os.environ.get("ACV_PACK", str(PROJECT_ROOT / "security_workers")))
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
            "tools": "GET /api/tools",
            "qualify": "POST /api/qualify",
            "audit": "POST /api/audit",
            "review": "POST /api/review",
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
        task_count = len(task_catalog(PACK_ROOT))
    except Exception:
        task_count = 0
    return {
        "ok": True,
        "provider": "groq",
        "model": os.environ.get("ACV_LLM_MODEL", DEFAULT_MODEL),
        "key_configured": GroqClient.is_configured(),
        "tasks": task_count,
        "version": __version__,
        "ui": WEB_ROOT.is_dir(),
    }


@app.get("/api/tasks")
def tasks() -> list[dict[str, object]]:
    """Return the task and candidate catalog used by the UI selectors."""

    try:
        return task_catalog(PACK_ROOT)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/tasks/{task_id}")
def task_detail(task_id: str) -> dict[str, object]:
    """Return the vulnerable source and the complete candidate set for one task."""

    try:
        task = load_task(PACK_ROOT / task_id)
    except ManifestError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _task_detail(task)


@app.post("/api/verify")
def verify(request: VerifyRequest) -> dict[str, object]:
    """Run the deterministic gate without a model."""

    try:
        task = load_task(PACK_ROOT / request.task_id)
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
        task = load_task(PACK_ROOT / request.task_id)
    except ManifestError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    result = evaluate_source(task, request.code, primary_checker=request.checker)
    return asdict(result)


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
        scores = evaluate_checkers(PACK_ROOT, names)
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"scores": [asdict(score) for score in scores]}


@app.post("/api/audit")
def audit() -> dict[str, object]:
    """Run the complete two-sided audit."""

    try:
        results = run_audit(PACK_ROOT)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return build_payload(results)


@app.post("/api/review", response_model=ReviewResult)
def review(request: ReviewRequest) -> ReviewResult:
    """Run one live model review and the deterministic gate."""

    try:
        return review_by_id(
            PACK_ROOT,
            task_id=request.task_id,
            candidate_name=request.candidate,
            model=request.model,
        )
    except ReviewError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except GroqError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


if WEB_ROOT.is_dir():
    app.mount("/static", StaticFiles(directory=str(WEB_ROOT)), name="static")
