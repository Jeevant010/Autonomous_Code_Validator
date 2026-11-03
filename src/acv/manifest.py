"""Load and validate security worker tasks."""

from __future__ import annotations

from pathlib import Path

from pydantic import ValidationError

from .models import TaskManifest, TaskSpec


class ManifestError(ValueError):
    """Raised when a task manifest or its files are not usable."""


def _inside(root: Path, relative: str, label: str) -> Path:
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ManifestError(f"{label} escapes the task directory: {relative}")
    if not path.exists():
        raise ManifestError(f"{label} does not exist: {relative}")
    return path


def load_task(task_root: Path) -> TaskSpec:
    task_root = task_root.resolve()
    manifest_path = task_root / "task.json"
    if not manifest_path.exists():
        raise ManifestError(f"missing task.json in {task_root}")
    try:
        manifest = TaskManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    except (ValidationError, ValueError) as exc:
        raise ManifestError(f"{manifest_path}: {exc}") from exc

    root = task_root
    data_dir = _inside(root, manifest.data_dir, "data_dir")
    if not data_dir.is_dir():
        raise ManifestError(f"data_dir is not a directory: {manifest.data_dir}")

    for candidate in manifest.candidates:
        _inside(root, candidate.path, f"candidate {candidate.name}")

    return TaskSpec(
        task_id=manifest.id,
        title=manifest.title,
        cwe=manifest.cwe,
        summary=manifest.summary,
        root=root,
        vulnerable=_inside(root, manifest.vulnerable, "vulnerable"),
        fixed=_inside(root, manifest.fixed, "fixed"),
        poc=_inside(root, manifest.poc, "poc"),
        functional=_inside(root, manifest.functional, "functional"),
        data_dir=data_dir,
        tags=manifest.tags,
        candidates=manifest.candidates,
    )


def discover_tasks(pack_root: Path) -> list[TaskSpec]:
    pack_root = pack_root.resolve()
    if not pack_root.is_dir():
        raise ManifestError(f"security pack not found: {pack_root}")
    tasks = [
        load_task(child)
        for child in sorted(pack_root.iterdir())
        if child.is_dir() and (child / "task.json").exists()
    ]
    if not tasks:
        raise ManifestError(f"no tasks found under {pack_root}")
    ids = [task.task_id for task in tasks]
    if len(ids) != len(set(ids)):
        raise ManifestError("duplicate task ids")
    return tasks
