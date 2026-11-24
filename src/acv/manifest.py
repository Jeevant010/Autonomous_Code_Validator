"""Load and validate security worker tasks."""

from __future__ import annotations

from collections.abc import Iterable
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


def discover_tasks_multi(roots: Iterable[Path]) -> list[TaskSpec]:
    """Discover tasks from multiple pack roots, rejecting duplicate ids."""

    tasks: list[TaskSpec] = []
    seen: dict[str, Path] = {}
    for raw_root in roots:
        root = raw_root.resolve()
        if not root.is_dir():
            continue
        for child in sorted(root.iterdir()):
            if not child.is_dir() or not (child / "task.json").exists():
                continue
            task = load_task(child)
            previous = seen.get(task.task_id)
            if previous is not None:
                raise ManifestError(
                    f"duplicate task id {task.task_id!r} in {previous} and {child}"
                )
            seen[task.task_id] = child
            tasks.append(task)
    if not tasks:
        raise ManifestError("no tasks found in the configured pack roots")
    return tasks


def find_task(roots: Iterable[Path], task_id: str) -> TaskSpec:
    """Find a task by id in the configured roots, in root order."""

    if not task_id or "/" in task_id or "\\" in task_id or task_id in {".", ".."}:
        raise ManifestError(f"invalid task id: {task_id!r}")
    for root in roots:
        candidate = (Path(root) / task_id).resolve()
        if not candidate.is_relative_to(Path(root).resolve()):
            continue
        if candidate.is_dir() and (candidate / "task.json").exists():
            return load_task(candidate)
    raise ManifestError(f"task not found: {task_id}")
