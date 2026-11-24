"""Task records for real-repository verification.

A repo task is deliberately small, because the repository already provides the
code and the tests. The task only pins the evidence: what to clone, which
commit, and which trusted PoC and behaviour suite judge it.
"""

from __future__ import annotations

import json
from pathlib import Path

from .repo_intake import RepoIntakeError, RepoSpec

DEFAULT_PACK = Path("repo_tasks")


def load_repo_task(task_dir: Path) -> RepoSpec:
    manifest_path = task_dir / "task.json"
    if not manifest_path.is_file():
        raise RepoIntakeError(f"missing task.json in {task_dir}")

    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise RepoIntakeError(f"invalid task.json in {task_dir}: {exc}") from exc

    required = ("id", "title", "cwe", "repo_url", "commit")
    missing = [field for field in required if not str(payload.get(field, "")).strip()]
    if missing:
        raise RepoIntakeError(f"task.json in {task_dir} is missing: {', '.join(missing)}")

    poc = task_dir / payload.get("poc", "poc/exploit.py")
    functional = str(payload.get("functional", "tests/test_functional.py"))
    if not poc.is_file():
        raise RepoIntakeError(f"poc file does not exist: {poc}")
    # A repo-prefixed functional path names a test file inside the repository,
    # so it is validated against the clone at run time rather than here.
    if not functional.startswith("repo:") and not (task_dir / functional).is_file():
        raise RepoIntakeError(f"functional file does not exist: {task_dir / functional}")

    return RepoSpec(
        task_id=str(payload["id"]),
        title=str(payload["title"]),
        cwe=str(payload["cwe"]),
        summary=str(payload.get("summary", "")),
        repo_url=str(payload["repo_url"]),
        commit=str(payload["commit"]),
        task_dir=task_dir.resolve(),
        fix_commit=str(payload.get("fix_commit", "")),
        fix_tag=str(payload.get("fix_tag", "")),
        diff_paths=tuple(payload.get("diff_paths", [])),
        bootstrap=tuple(payload.get("bootstrap", [])),
        poc=str(payload.get("poc", "poc/exploit.py")),
        functional=functional,
        checker_include=tuple(payload.get("checker_include", ["**/*.py"])),
        checker_exclude=tuple(
            payload.get(
                "checker_exclude",
                ["tests/**", "poc/**", "**/__pycache__/**", "**/.pytest_cache/**"],
            )
        ),
        install_targets=tuple(payload.get("install_targets", [])),
        python_path_extra=tuple(payload.get("python_path_extra", [])),
        source_root=str(payload.get("source_root", "src")),
        memory_mb=int(payload.get("memory_mb", 768)),
        poc_timeout=int(payload.get("poc_timeout", 120)),
        test_timeout=int(payload.get("test_timeout", 600)),
        protected_paths=tuple(payload.get("protected_paths", [])),
    )


def discover_repo_tasks(pack_root: Path = DEFAULT_PACK) -> list[RepoSpec]:
    root = pack_root.resolve()
    if not root.is_dir():
        return []
    tasks: list[RepoSpec] = []
    for candidate in sorted(root.iterdir()):
        if (candidate / "task.json").is_file():
            tasks.append(load_repo_task(candidate))
    return tasks


def find_repo_task(task_id: str, pack_root: Path = DEFAULT_PACK) -> RepoSpec:
    root = pack_root.resolve()
    direct = root / task_id
    if (direct / "task.json").is_file():
        return load_repo_task(direct)
    for task in discover_repo_tasks(pack_root):
        if task.task_id == task_id:
            return task
    known = ", ".join(task.task_id for task in discover_repo_tasks(pack_root)) or "none"
    raise RepoIntakeError(f"unknown repo task {task_id!r}; known tasks: {known}")
