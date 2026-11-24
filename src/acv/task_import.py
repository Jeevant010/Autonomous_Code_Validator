"""Import a self-contained task bundle into the user task pack.

The bundle is data, not executable input. Import validates the manifest and
required paths, writes to a staging directory, then asks the normal task loader
to validate the result before publishing it. It does not run the exploit or the
candidate.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, Field, ValidationError

from .manifest import ManifestError, load_task
from .models import TaskManifest, TaskSpec

MAX_FILE_CHARS = 200_000
MAX_FILES = 40


class TaskImportError(ValueError):
    """Raised when a task bundle is unsafe or incomplete."""


class TaskBundle(BaseModel):
    """A manifest plus the files it references, all relative to the task root."""

    manifest: TaskManifest
    files: dict[str, str] = Field(default_factory=dict)


def _safe_relative(raw: str, label: str) -> str:
    if not raw or raw != raw.strip():
        raise TaskImportError(f"{label} must be a non-empty relative path")
    if "\\" in raw or raw.startswith("/"):
        raise TaskImportError(f"{label} must use POSIX relative paths: {raw!r}")
    path = PurePosixPath(raw)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise TaskImportError(f"{label} escapes the task directory: {raw!r}")
    normalized = path.as_posix()
    if normalized == "task.json":
        raise TaskImportError("task.json is generated from the manifest; do not supply it")
    return normalized


def _required_paths(manifest: TaskManifest) -> set[str]:
    required = {
        _safe_relative(manifest.vulnerable, "vulnerable"),
        _safe_relative(manifest.fixed, "fixed"),
        _safe_relative(manifest.poc, "poc"),
        _safe_relative(manifest.functional, "functional"),
    }
    for candidate in manifest.candidates:
        required.add(_safe_relative(candidate.path, f"candidate {candidate.name}"))
    return required


def validate_bundle(bundle: TaskBundle) -> TaskManifest:
    """Validate paths and required files without writing anything."""

    manifest = bundle.manifest
    _safe_relative(manifest.data_dir, "data_dir")
    required = _required_paths(manifest)
    files = {_safe_relative(name, "file"): text for name, text in bundle.files.items()}

    missing = sorted(required - files.keys())
    if missing:
        raise TaskImportError(f"missing required files: {', '.join(missing)}")
    if len(files) > MAX_FILES:
        raise TaskImportError(f"bundle has too many files ({len(files)} > {MAX_FILES})")

    total = 0
    for name, text in files.items():
        if not isinstance(text, str):
            raise TaskImportError(f"{name} must contain text")
        total += len(text)
        if len(text) > MAX_FILE_CHARS:
            raise TaskImportError(f"{name} is larger than {MAX_FILE_CHARS} characters")
    if total > MAX_FILE_CHARS * 4:
        raise TaskImportError("bundle is too large")

    return manifest


def import_bundle(bundle: TaskBundle, root: Path, overwrite: bool = False) -> Path:
    """Validate and publish a bundle under ``root/<task_id>``."""

    manifest = validate_bundle(bundle)
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    dest = (root / manifest.id).resolve()
    if not dest.is_relative_to(root):
        raise TaskImportError("task id escapes the user pack")
    if dest.exists() and not overwrite:
        raise TaskImportError(f"task {manifest.id!r} already exists in the user pack")

    staging = Path(tempfile.mkdtemp(prefix=f".import-{manifest.id}-", dir=root))
    try:
        for raw_name, text in bundle.files.items():
            name = _safe_relative(raw_name, "file")
            path = (staging / name).resolve()
            if not path.is_relative_to(staging):
                raise TaskImportError(f"file escapes the task directory: {raw_name!r}")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

        data_dir = (staging / manifest.data_dir).resolve()
        if not data_dir.is_relative_to(staging):
            raise TaskImportError("data_dir escapes the task directory")
        data_dir.mkdir(parents=True, exist_ok=True)
        (staging / "task.json").write_text(
            manifest.model_dump_json(indent=2) + "\n",
            encoding="utf-8",
        )

        try:
            load_task(staging)
        except (ManifestError, ValidationError, ValueError) as exc:
            raise TaskImportError(f"bundle does not form a valid task: {exc}") from exc

        if dest.exists():
            shutil.rmtree(dest)
        staging.rename(dest)
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
    return dest


def bundle_from_task(task: TaskSpec, task_id: str | None = None) -> TaskBundle:
    """Build an editable bundle from an existing fixture, for the UI template."""

    raw = json.loads((task.root / "task.json").read_text(encoding="utf-8"))
    if task_id:
        raw["id"] = task_id
    files: dict[str, str] = {}
    paths = [task.vulnerable, task.fixed, task.poc, task.functional]
    paths.extend(task.root / candidate.path for candidate in task.candidates)
    for path in paths:
        relative = path.relative_to(task.root).as_posix()
        files[relative] = path.read_text(encoding="utf-8")
    for path in sorted(task.data_dir.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            relative = path.relative_to(task.root).as_posix()
            files[relative] = path.read_text(encoding="utf-8", errors="replace")
    return TaskBundle(manifest=TaskManifest.model_validate(raw), files=files)
