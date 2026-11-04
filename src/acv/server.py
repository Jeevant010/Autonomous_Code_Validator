"""Local web app and live review API.

The server keeps the Groq key on the machine. The browser never sees it.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles

from . import __version__
from .llm import GroqClient, GroqError
from .review import ReviewError, ReviewRequest, ReviewResult, review_by_id, task_catalog

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PRESENTATION_DIR = PROJECT_ROOT / "presentation"
PACK_ROOT = Path(os.environ.get("ACV_PACK", str(PROJECT_ROOT / "security_workers")))

app = FastAPI(
    title="Autonomous Code Validator",
    version=__version__,
    description="Deterministic gate plus a live model reviewer.",
)


@app.get("/api/health")
def health() -> dict[str, object]:
    """Report whether the live reviewer is configured without exposing the key."""
    try:
        tasks = task_catalog(PACK_ROOT)
        task_count = len(tasks)
    except Exception:
        task_count = 0
    return {
        "ok": True,
        "provider": "groq",
        "model": os.environ.get("ACV_LLM_MODEL", "openai/gpt-oss-120b"),
        "key_configured": GroqClient.is_configured(),
        "tasks": task_count,
        "version": __version__,
    }


@app.get("/api/tasks")
def tasks() -> list[dict[str, object]]:
    """Return the task and candidate catalog used by the live selector."""
    try:
        return task_catalog(PACK_ROOT)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


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


# Mount the static presentation last so /api routes win.
app.mount(
    "/",
    StaticFiles(directory=str(PRESENTATION_DIR), html=True),
    name="presentation",
)
