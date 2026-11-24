"""Multi-file project verification.

The single-file worker pack is deliberately small: it is a calibration set. This
module adds the other shape of evidence a real reviewer needs: a complete
project tree, a trusted exploit and functional test outside that tree, and an
overlay of changed files produced by any generator.

Two boundaries matter and are stated plainly:

* The gate is still executable evidence. ``oracle_ok``, ``security_pass``,
  ``behavior_pass``, and ``checker_pass`` are all required.
* Execution uses the same process limits as the single-file runner. That is not
  network or filesystem isolation. The caller is responsible for running this on
  a trusted machine, and critical code should be moved to a VM or container.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import ValidationError

from .checkers import CheckerAdapter, checker_adapters
from .models import (
    CheckerResult,
    CheckFinding,
    ProjectFileInfo,
    ProjectManifest,
    ProjectProvenance,
    ProjectResult,
    ProjectSpec,
)
from .sandbox import SandboxPolicy
from .sandbox import run as run_sandboxed
from .verdict import classify_poc

CheckerName = Literal["acv-rules", "bandit", "semgrep"]

MAX_OVERLAY_FILES = 250
MAX_OVERLAY_CHARS = 1_500_000
MAX_OVERLAY_FILE_CHARS = 400_000
MAX_CHECKER_FILES = 250
MAX_FINDINGS = 500
MAX_CHECKER_FILE_BYTES = 1_000_000
MAX_OUTPUT_CHARS = 4_000

SKIP_PARTS = {
    ".git",
    ".hg",
    ".svn",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    ".tox",
}
ALLOWED_OVERLAY_SUFFIXES = {
    ".py",
    ".json",
    ".txt",
    ".md",
    ".html",
    ".htm",
    ".css",
    ".js",
    ".yaml",
    ".yml",
    ".toml",
    ".sql",
    ".csv",
    ".ini",
    ".cfg",
    ".xml",
    ".j2",
    ".jinja",
    ".template",
}
# Files that can change how pytest imports the trusted evidence. A generated
# overlay must not be able to edit the judge.
BLOCKED_OVERLAY_NAMES = {
    "conftest.py",
    "pytest.ini",
    "tox.ini",
    "setup.cfg",
    "pyproject.toml",
    "sitecustomize.py",
    "usercustomize.py",
}
ISOLATION_WARNING = (
    "Executed with CPU, memory, output, and wall-clock limits only. There is no "
    "network namespace, filesystem jail, or container boundary. Use an isolated "
    "VM or container for untrusted or critical code."
)


class ProjectError(ValueError):
    """Raised when a project manifest, overlay, patch, or file is unusable."""


class ProjectLimitError(ProjectError):
    """Raised when a project exceeds an explicit size or count limit."""


def _inside(root: Path, relative: str, label: str) -> Path:
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ProjectError(f"{label} escapes the project directory: {relative}")
    if not path.exists():
        raise ProjectError(f"{label} does not exist: {relative}")
    return path


def _inside_dir(root: Path, relative: str, label: str) -> Path:
    path = _inside(root, relative, label)
    if not path.is_dir():
        raise ProjectError(f"{label} is not a directory: {relative}")
    return path


def _inside_file(root: Path, relative: str, label: str) -> Path:
    path = _inside(root, relative, label)
    if not path.is_file():
        raise ProjectError(f"{label} is not a file: {relative}")
    return path


def safe_relative(raw: str, label: str = "path") -> str:
    """Return a normalized POSIX relative path, or raise."""

    if not raw or raw != raw.strip():
        raise ProjectError(f"{label} must be a non-empty relative path")
    if "\\" in raw or raw.startswith("/"):
        raise ProjectError(f"{label} must use POSIX relative paths: {raw!r}")
    if "\x00" in raw:
        raise ProjectError(f"{label} contains a NUL byte")
    path = PurePosixPath(raw)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ProjectError(f"{label} escapes the project directory: {raw!r}")
    normalized = path.as_posix()
    if normalized in {".", ""}:
        raise ProjectError(f"{label} is not a file path: {raw!r}")
    return normalized


def _validate_overlay_name(raw: str, label: str = "file") -> str:
    normalized = safe_relative(raw, label)
    path = PurePosixPath(normalized)
    if any(part in SKIP_PARTS or part.startswith(".") for part in path.parts):
        raise ProjectError(f"{label} uses a blocked hidden or cache path: {raw!r}")
    if path.name in BLOCKED_OVERLAY_NAMES or path.suffix == ".pth":
        raise ProjectError(
            f"{label} may not replace harness or interpreter configuration: {raw!r}"
        )
    if path.suffix.lower() not in ALLOWED_OVERLAY_SUFFIXES:
        raise ProjectError(
            f"{label} has an unsupported suffix {path.suffix!r}; "
            f"allowed: {', '.join(sorted(ALLOWED_OVERLAY_SUFFIXES))}"
        )
    return normalized


def _iter_files(root: Path, *, reject_symlinks: bool = False) -> Iterator[Path]:
    """Yield regular files under ``root``, optionally rejecting symlinks."""

    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in SKIP_PARTS for part in relative.parts):
            continue
        if path.is_symlink():
            if reject_symlinks:
                raise ProjectError(f"project may not contain symlinks: {relative.as_posix()}")
            continue
        if path.is_file():
            yield path


def _base_inventory(root: Path, spec_max_files: int, spec_max_bytes: int) -> list[Path]:
    paths = list(_iter_files(root))
    if len(paths) > spec_max_files:
        raise ProjectLimitError(
            f"project base has {len(paths)} files, above the manifest limit of {spec_max_files}"
        )
    total = 0
    for path in paths:
        total += path.stat().st_size
    if total > spec_max_bytes:
        raise ProjectLimitError(
            f"project base is {total} bytes, above the manifest limit of {spec_max_bytes}"
        )
    return paths


def load_project(project_root: Path) -> ProjectSpec:
    """Load and validate one multi-file project task."""

    project_root = project_root.resolve()
    manifest_path = project_root / "task.json"
    if not manifest_path.exists():
        raise ProjectError(f"missing task.json in {project_root}")
    try:
        manifest = ProjectManifest.model_validate_json(
            manifest_path.read_text(encoding="utf-8")
        )
    except (ValidationError, ValueError) as exc:
        raise ProjectError(f"{manifest_path}: {exc}") from exc

    vulnerable = _inside_dir(project_root, manifest.vulnerable, "vulnerable")
    poc = _inside_file(project_root, manifest.poc, "poc")
    functional = _inside_file(project_root, manifest.functional, "functional")
    data_dir = _inside_dir(project_root, manifest.data_dir, "data_dir")

    if vulnerable == project_root:
        raise ProjectError("vulnerable must be a subtree, not the whole task directory")
    for label, evidence in (("poc", poc), ("functional", functional)):
        if evidence.is_relative_to(vulnerable):
            raise ProjectError(f"{label} must live outside the generated base tree")

    _base_inventory(vulnerable, manifest.max_files, manifest.max_total_bytes)

    for candidate in manifest.candidates:
        _inside_dir(project_root, candidate.path, f"candidate {candidate.name}")

    return ProjectSpec(
        project_id=manifest.id,
        title=manifest.title,
        cwe=manifest.cwe,
        summary=manifest.summary,
        root=project_root,
        vulnerable=vulnerable,
        poc=poc,
        functional=functional,
        data_dir=data_dir,
        checker_include=manifest.checker_include,
        checker_exclude=manifest.checker_exclude,
        max_files=manifest.max_files,
        max_total_bytes=manifest.max_total_bytes,
        memory_mb=manifest.memory_mb,
        poc_timeout=manifest.poc_timeout,
        test_timeout=manifest.test_timeout,
        tags=manifest.tags,
        candidates=manifest.candidates,
    )


def discover_projects(pack_root: Path) -> list[ProjectSpec]:
    pack_root = pack_root.resolve()
    if not pack_root.is_dir():
        raise ProjectError(f"project pack not found: {pack_root}")
    projects = [
        load_project(child)
        for child in sorted(pack_root.iterdir())
        if child.is_dir() and (child / "task.json").exists()
    ]
    if not projects:
        raise ProjectError(f"no projects found under {pack_root}")
    ids = [project.project_id for project in projects]
    if len(ids) != len(set(ids)):
        raise ProjectError("duplicate project ids")
    return projects


def discover_projects_multi(roots: Iterable[Path]) -> list[ProjectSpec]:
    projects: list[ProjectSpec] = []
    seen: set[str] = set()
    for raw_root in roots:
        root = raw_root.resolve()
        if not root.is_dir():
            continue
        for child in sorted(root.iterdir()):
            if not child.is_dir() or not (child / "task.json").exists():
                continue
            project = load_project(child)
            if project.project_id in seen:
                raise ProjectError(
                    f"duplicate project id {project.project_id!r} in {root}"
                )
            seen.add(project.project_id)
            projects.append(project)
    if not projects:
        raise ProjectError("no projects found in the configured pack roots")
    return projects


def find_project(roots: Iterable[Path], project_id: str) -> ProjectSpec:
    if not project_id or "/" in project_id or "\\" in project_id or project_id in {".", ".."}:
        raise ProjectError(f"invalid project id: {project_id!r}")
    for root in roots:
        candidate = (Path(root) / project_id).resolve()
        if not candidate.is_relative_to(Path(root).resolve()):
            continue
        if candidate.is_dir() and (candidate / "task.json").exists():
            return load_project(candidate)
    raise ProjectError(f"project not found: {project_id}")


def _inventory(root: Path) -> list[ProjectFileInfo]:
    files: list[ProjectFileInfo] = []
    for path in _iter_files(root):
        relative = path.relative_to(root).as_posix()
        data = path.read_bytes()
        try:
            text = data.decode("utf-8")
            lines = len(text.splitlines())
        except UnicodeDecodeError:
            lines = 0
        role = "source"
        if relative == "data" or relative.startswith("data/"):
            role = "data"
        elif relative.startswith("tests/"):
            role = "test"
        elif relative.startswith("poc/"):
            role = "poc"
        files.append(
            ProjectFileInfo(
                path=relative,
                bytes=len(data),
                lines=lines,
                sha256=hashlib.sha256(data).hexdigest(),
                role=role,
            )
        )
    return files


def _copy_tree(source: Path, destination: Path, spec: ProjectSpec) -> list[str]:
    copied: list[str] = []
    total = 0
    for path in _iter_files(source, reject_symlinks=True):
        relative = path.relative_to(source)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        copied.append(relative.as_posix())
        total += path.stat().st_size
        if len(copied) > spec.max_files:
            raise ProjectLimitError(
                f"project has more than {spec.max_files} files after preparation"
            )
        if total > spec.max_total_bytes:
            raise ProjectLimitError(
                f"project is larger than {spec.max_total_bytes} bytes after preparation"
            )
    return copied


def validate_overlay(files: dict[str, str], spec: ProjectSpec | None = None) -> dict[str, str]:
    """Validate an uploaded or generated file overlay without writing it."""

    if len(files) > MAX_OVERLAY_FILES:
        raise ProjectLimitError(
            f"overlay has {len(files)} files, above the limit of {MAX_OVERLAY_FILES}"
        )
    total = 0
    normalized: dict[str, str] = {}
    for raw_name, text in files.items():
        name = _validate_overlay_name(raw_name)
        if not isinstance(text, str):
            raise ProjectError(f"{name} must contain text")
        size = len(text.encode("utf-8"))
        if size > MAX_OVERLAY_FILE_CHARS:
            raise ProjectLimitError(
                f"{name} is {size} bytes, above the "
                f"{MAX_OVERLAY_FILE_CHARS} byte file limit"
            )
        total += size
        if total > MAX_OVERLAY_CHARS:
            raise ProjectLimitError(
                f"overlay is larger than {MAX_OVERLAY_CHARS} bytes"
            )
        normalized[name] = text
    if spec is not None:
        if len(normalized) > spec.max_files:
            raise ProjectLimitError(
                f"overlay has {len(normalized)} files, above the project limit of {spec.max_files}"
            )
        if total > spec.max_total_bytes:
            raise ProjectLimitError(
                f"overlay is {total} bytes, above the project limit of "
                f"{spec.max_total_bytes} bytes"
            )
    return normalized


def _write_overlay(workdir: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        target = (workdir / name).resolve()
        if not target.is_relative_to(workdir):
            raise ProjectError(f"overlay file escapes the project: {name!r}")
        if target.is_symlink():
            raise ProjectError(f"overlay may not follow a symlink: {name!r}")
        if target.exists() and target.is_dir():
            raise ProjectError(f"overlay path is a directory: {name!r}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")


@contextmanager
def materialize(
    spec: ProjectSpec,
    overlay: dict[str, str] | None = None,
) -> Iterator[Path]:
    """Copy the base tree and apply an overlay in a temporary work directory."""

    validated = validate_overlay(overlay or {}, spec)
    with tempfile.TemporaryDirectory(prefix=f"acv-project-{spec.project_id}-") as temp:
        workdir = Path(temp) / "project"
        workdir.mkdir(parents=True)
        _copy_tree(spec.vulnerable, workdir, spec)
        if spec.data_dir.is_dir():
            data_target = workdir / "data"
            data_target.mkdir(parents=True, exist_ok=True)
            _copy_tree(spec.data_dir, data_target, spec)
        _write_overlay(workdir, validated)
        prepared = list(_iter_files(workdir, reject_symlinks=True))
        if len(prepared) > spec.max_files:
            raise ProjectLimitError(
                f"prepared project has {len(prepared)} files, above the "
                f"manifest limit of {spec.max_files}"
            )
        prepared_bytes = sum(path.stat().st_size for path in prepared)
        if prepared_bytes > spec.max_total_bytes:
            raise ProjectLimitError(
                f"prepared project is {prepared_bytes} bytes, above the "
                f"manifest limit of {spec.max_total_bytes}"
            )
        yield workdir


def _environment(spec: ProjectSpec, workdir: Path) -> dict[str, str]:
    env = os.environ.copy()
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(workdir) + (os.pathsep + existing if existing else "")
    env["ACV_PROJECT_ID"] = spec.project_id
    env["ACV_PROJECT_ROOT"] = str(workdir)
    env["ACV_DATA_DIR"] = str(workdir / "data")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONHASHSEED"] = "0"
    env["NO_PROXY"] = "*"
    env["no_proxy"] = "*"
    return env


def _run(
    command: list[str],
    spec: ProjectSpec,
    workdir: Path,
    timeout: int,
) -> tuple[int, str]:
    policy = SandboxPolicy(
        timeout=float(timeout),
        cpu_seconds=max(timeout, 1),
        memory_mb=spec.memory_mb,
        file_size_mb=32,
        max_output_bytes=2_000_000,
    )
    return run_sandboxed(
        command,
        cwd=workdir,
        env=_environment(spec, workdir),
        policy=policy,
        scratch_dir=workdir.parent / "scratch",
    )


def run_project_poc(spec: ProjectSpec, workdir: Path) -> tuple[int, str]:
    return _run(
        [sys.executable, str(spec.poc)],
        spec,
        workdir,
        timeout=spec.poc_timeout,
    )


def run_project_functional(spec: ProjectSpec, workdir: Path) -> tuple[int, str]:
    return _run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(spec.functional),
            "-q",
            "-p",
            "no:cacheprovider",
            "--rootdir",
            str(spec.root),
        ],
        spec,
        workdir,
        timeout=spec.test_timeout,
    )


def _relative_match(relative: str, pattern: str) -> bool:
    return fnmatch.fnmatch(relative, pattern)


def checker_files(spec: ProjectSpec, root: Path) -> list[Path]:
    """Return the source files selected by the manifest's checker scope."""

    selected: dict[str, Path] = {}
    for pattern in spec.checker_include:
        for path in root.glob(pattern):
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
            if any(part in SKIP_PARTS for part in path.relative_to(root).parts):
                continue
            if any(_relative_match(relative, excluded) for excluded in spec.checker_exclude):
                continue
            selected[relative] = path
    return [selected[name] for name in sorted(selected)]


def run_project_checkers(spec: ProjectSpec, root: Path) -> dict[str, CheckerResult]:
    """Run every checker across the project's source files."""

    files = checker_files(spec, root)
    adapters: tuple[CheckerAdapter, ...] = checker_adapters()
    results: dict[str, CheckerResult] = {}

    for adapter in adapters:
        if not adapter.available:
            results[adapter.name] = CheckerResult(
                tool=adapter.name,
                available=False,
                version=adapter.version,
                error="checker is not installed",
            )
            continue

        findings: list[CheckFinding] = []
        errors: dict[str, str] = {}
        scanned = 0
        truncated = len(files) > MAX_CHECKER_FILES
        for path in files[:MAX_CHECKER_FILES]:
            relative = path.relative_to(root).as_posix()
            if path.stat().st_size > MAX_CHECKER_FILE_BYTES:
                errors[relative] = (
                    f"skipped: {path.stat().st_size} bytes is above the "
                    f"{MAX_CHECKER_FILE_BYTES} byte checker limit"
                )
                continue
            try:
                result = adapter.run(path)
            except Exception as exc:  # A checker must not take down the gate.
                errors[relative] = f"{type(exc).__name__}: {exc}"[:500]
                continue
            if not result.available:
                errors[relative] = result.error or "checker unavailable for this file"
                continue
            scanned += 1
            for finding in result.findings:
                findings.append(replace(finding, path=finding.path or relative))
                if len(findings) >= MAX_FINDINGS:
                    truncated = True
                    break
            if len(findings) >= MAX_FINDINGS:
                break

        error_text = "; ".join(
            f"{name}: {message}" for name, message in list(errors.items())[:12]
        )
        if len(errors) > 12:
            error_text += f"; ... {len(errors) - 12} more files"
        results[adapter.name] = CheckerResult(
            tool=adapter.name,
            available=True,
            findings=findings[:MAX_FINDINGS],
            version=adapter.version,
            error=error_text or None,
            files_scanned=scanned,
            truncated=truncated,
            coverage_complete=(
                bool(files) and not errors and not truncated and scanned == len(files)
            ),
            errors=errors,
        )
    return results


def _select_primary(
    checker_results: dict[str, CheckerResult],
    primary_checker: CheckerName,
) -> tuple[CheckerResult, str]:
    primary = checker_results.get(primary_checker)
    if primary is None or not primary.available:
        return checker_results["acv-rules"], "acv-rules"
    return primary, primary_checker


def _clip_output(text: str) -> tuple[str, bool]:
    stripped = text.strip()
    if len(stripped) <= MAX_OUTPUT_CHARS:
        return stripped, False
    return stripped[-MAX_OUTPUT_CHARS:], True


def _oracle(spec: ProjectSpec) -> tuple[int, str]:
    with materialize(spec, {}) as workdir:
        return run_project_poc(spec, workdir)


def _reasons(
    oracle_ok: bool,
    oracle_exit: int,
    poc_verdict: str,
    behavior_exit: int,
    primary: CheckerResult,
) -> list[str]:
    reasons: list[str] = []
    if not oracle_ok:
        reasons.append(
            f"oracle did not reproduce on the vulnerable project (exit {oracle_exit})"
        )
    if poc_verdict == "vulnerable":
        reasons.append("PoC still succeeds")
    elif poc_verdict == "error":
        reasons.append("PoC could not reach a verdict: the candidate crashed or the fixture broke")
    if behavior_exit != 0:
        reasons.append("functional suite fails")
    if not primary.passed:
        ids = ", ".join(sorted({finding.rule_id for finding in primary.blocking}))
        reasons.append(f"checker findings: {ids or 'unavailable'}")
    elif not primary.coverage_complete:
        reasons.append(
            "checker coverage is incomplete: a source file was skipped, unreadable, "
            "or the file/finding cap was reached"
        )
    return reasons


def _evaluate_workdir(
    spec: ProjectSpec,
    workdir: Path,
    *,
    input_mode: str,
    overlay_files: list[str],
    diff_applied: bool,
    oracle_exit: int,
    oracle_output: str,
    provenance: ProjectProvenance,
    primary_checker: CheckerName,
    started: float,
) -> ProjectResult:
    oracle_ok = oracle_exit == 0
    poc_exit, poc_output = run_project_poc(spec, workdir)
    behavior_exit, behavior_output = run_project_functional(spec, workdir)
    checker_results = run_project_checkers(spec, workdir)
    primary, checker_tool = _select_primary(checker_results, primary_checker)

    poc_verdict = classify_poc(poc_exit, poc_output)
    security_pass = poc_verdict == "blocked"
    behavior_pass = behavior_exit == 0
    checker_pass = primary.passed and primary.coverage_complete
    accepted = oracle_ok and security_pass and behavior_pass and checker_pass
    reasons = _reasons(oracle_ok, oracle_exit, poc_verdict, behavior_exit, primary)

    files = _inventory(workdir)
    total_bytes = sum(item.bytes for item in files)
    total_lines = sum(item.lines for item in files)
    clipped_poc, poc_truncated = _clip_output(poc_output)
    clipped_behavior, behavior_truncated = _clip_output(behavior_output)
    clipped_oracle, oracle_truncated = _clip_output(oracle_output)

    return ProjectResult(
        project_id=spec.project_id,
        project_title=spec.title,
        cwe=spec.cwe,
        summary=spec.summary,
        run_id=uuid.uuid4().hex,
        input_mode=input_mode,  # type: ignore[arg-type]
        overlay_files=sorted(overlay_files),
        files=files,
        total_files=len(files),
        total_bytes=total_bytes,
        total_lines=total_lines,
        poc_exit=poc_exit,
        behavior_exit=behavior_exit,
        poc_output=clipped_poc,
        behavior_output=clipped_behavior,
        poc_output_truncated=poc_truncated,
        behavior_output_truncated=behavior_truncated,
        security_pass=security_pass,
        behavior_pass=behavior_pass,
        checker_pass=checker_pass,
        accepted=accepted,
        oracle_exit=oracle_exit,
        oracle_output=clipped_oracle,
        oracle_output_truncated=oracle_truncated,
        oracle_ok=oracle_ok,
        diff_applied=diff_applied,
        reasons=reasons,
        findings=primary.findings,
        checker_tool=checker_tool,
        checker_results=checker_results,
        provenance=provenance,
        isolation="process-limits-only",
        isolation_warning=ISOLATION_WARNING,
        findings_truncated=any(result.truncated for result in checker_results.values()),
        elapsed_ms=int((time.perf_counter() - started) * 1000),
        poc_verdict=poc_verdict,
    )


def evaluate_project(
    spec: ProjectSpec,
    overlay: dict[str, str] | None = None,
    *,
    input_mode: str = "overlay",
    provenance: ProjectProvenance | None = None,
    primary_checker: CheckerName = "acv-rules",
) -> ProjectResult:
    """Verify a generated overlay against the trusted project evidence."""

    started = time.perf_counter()
    validated = validate_overlay(overlay or {}, spec)
    oracle_exit, oracle_output = _oracle(spec)
    with materialize(spec, validated) as workdir:
        return _evaluate_workdir(
            spec,
            workdir,
            input_mode=input_mode,
            overlay_files=list(validated),
            diff_applied=False,
            oracle_exit=oracle_exit,
            oracle_output=oracle_output,
            provenance=provenance or ProjectProvenance(),
            primary_checker=primary_checker,
            started=started,
        )


def load_candidate_overlay(spec: ProjectSpec, name: str) -> dict[str, str]:
    candidate = next(
        (item for item in spec.candidates if item.name == name),
        None,
    )
    if candidate is None:
        raise ProjectError(f"unknown project candidate: {name}")
    directory = _inside_dir(spec.root, candidate.path, f"candidate {name}")
    files: dict[str, str] = {}
    for path in _iter_files(directory):
        relative = path.relative_to(directory).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ProjectError(f"candidate {name} contains a non-text file: {relative}") from exc
        files[relative] = text
    return validate_overlay(files, spec)


def evaluate_project_candidate(
    spec: ProjectSpec,
    name: str,
    *,
    provenance: ProjectProvenance | None = None,
    primary_checker: CheckerName = "acv-rules",
) -> ProjectResult:
    return evaluate_project(
        spec,
        load_candidate_overlay(spec, name),
        input_mode="candidate",
        provenance=provenance,
        primary_checker=primary_checker,
    )


def _diff_header_path(raw: str) -> str:
    raw = raw.strip().split("\t", 1)[0].strip()
    if raw == "/dev/null":
        return raw
    return _validate_overlay_name(
        raw.removeprefix("a/").removeprefix("b/"),
        "diff target",
    )


def validate_project_diff(diff: str) -> list[str]:
    """Validate the file targets of a unified diff before applying it.

    Only text changes to existing project files are accepted. Renames, copies,
    symlinks, submodules, and binary patches are rejected because they change
    the project shape in ways the evidence tree does not describe.
    """

    if not diff.strip():
        raise ProjectError("diff is empty")
    targets: set[str] = set()
    header_lines = 0
    for line in diff.splitlines():
        if line.startswith("new file mode ") or line.startswith("deleted file mode "):
            mode = line.rsplit(" ", 1)[-1]
            if mode in {"120000", "160000"}:
                raise ProjectError("diff may not add a symlink or submodule")
        if line.startswith(("rename from ", "rename to ", "copy from ", "copy to ")):
            raise ProjectError("diff may not rename or copy project files")
        if line.startswith("Binary files "):
            raise ProjectError("diff may not add or modify binary files")
        if line.startswith("diff --git "):
            header_lines += 1
            parts = line[len("diff --git ") :].split()
            if len(parts) < 2:
                raise ProjectError(f"diff has an invalid git header: {line!r}")
            for raw in parts[:2]:
                _diff_header_path(raw)
            continue
        if not line.startswith(("--- ", "+++ ")):
            continue
        header_lines += 1
        raw = line[4:]
        if raw.strip() == "/dev/null":
            continue
        targets.add(_diff_header_path(raw))
    if not targets or not header_lines:
        raise ProjectError("diff has no project file target")
    return sorted(targets)


def apply_project_diff(workdir: Path, diff: str) -> None:
    targets = validate_project_diff(diff)
    diff_path = workdir / ".acv-change.diff"
    diff_path.write_text(diff, encoding="utf-8")
    for command in (
        ["git", "apply", "--check", "-p1", ".acv-change.diff"],
        ["git", "apply", "-p1", ".acv-change.diff"],
    ):
        try:
            proc = subprocess.run(
                command,
                cwd=workdir,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProjectError(f"could not run git apply: {exc}") from exc
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip()
            raise ProjectError(f"diff did not apply: {detail or 'git apply failed'}")
    # The diff file is harness state, not part of the project evidence.
    diff_path.unlink(missing_ok=True)
    for path in workdir.rglob("*"):
        if path.is_symlink():
            raise ProjectError(f"diff created a symlink, which is not allowed: {path.name}")
    missing = [name for name in targets if not (workdir / name).exists()]
    if missing:
        raise ProjectError(f"diff deleted required project files: {', '.join(missing)}")


def evaluate_project_patch(
    spec: ProjectSpec,
    diff: str,
    *,
    provenance: ProjectProvenance | None = None,
    primary_checker: CheckerName = "acv-rules",
) -> ProjectResult:
    """Apply a multi-file unified diff to the base project and gate it."""

    started = time.perf_counter()
    targets = validate_project_diff(diff)
    oracle_exit, oracle_output = _oracle(spec)
    with materialize(spec, {}) as workdir:
        apply_project_diff(workdir, diff)
        _base_inventory(workdir, spec.max_files, spec.max_total_bytes)
        return _evaluate_workdir(
            spec,
            workdir,
            input_mode="diff",
            overlay_files=targets,
            diff_applied=True,
            oracle_exit=oracle_exit,
            oracle_output=oracle_output,
            provenance=provenance or ProjectProvenance(),
            primary_checker=primary_checker,
            started=started,
        )


def project_catalog(projects: Iterable[ProjectSpec]) -> list[dict[str, object]]:
    catalog: list[dict[str, object]] = []
    for project in projects:
        files = _inventory(project.vulnerable)
        catalog.append(
            {
                "project_id": project.project_id,
                "title": project.title,
                "cwe": project.cwe,
                "summary": project.summary,
                "tags": list(project.tags),
                "files": len(files),
                "lines": sum(item.lines for item in files),
                "bytes": sum(item.bytes for item in files),
                "candidates": [
                    {
                        "name": candidate.name,
                        "kind": candidate.kind,
                        "expected_security": candidate.expected_security,
                        "expected_behavior": candidate.expected_behavior,
                        "note": candidate.note,
                    }
                    for candidate in project.candidates
                ],
            }
        )
    return catalog


def project_detail(project: ProjectSpec) -> dict[str, object]:
    files = _inventory(project.vulnerable)
    return {
        "project_id": project.project_id,
        "title": project.title,
        "cwe": project.cwe,
        "summary": project.summary,
        "tags": list(project.tags),
        "root": str(project.root),
        "paths": {
            "vulnerable": str(project.vulnerable),
            "poc": str(project.poc),
            "functional": str(project.functional),
            "data": str(project.data_dir),
        },
        "limits": {
            "max_files": project.max_files,
            "max_total_bytes": project.max_total_bytes,
            "memory_mb": project.memory_mb,
            "poc_timeout": project.poc_timeout,
            "test_timeout": project.test_timeout,
            "overlay_files": MAX_OVERLAY_FILES,
            "overlay_chars": MAX_OVERLAY_CHARS,
            "checker_findings": MAX_FINDINGS,
        },
        "files": [file.__dict__ for file in files],
        "checker_scope": [
            path.relative_to(project.vulnerable).as_posix()
            for path in checker_files(project, project.vulnerable)
        ],
        "total_files": len(files),
        "total_lines": sum(item.lines for item in files),
        "total_bytes": sum(item.bytes for item in files),
        "poc": project.poc.read_text(encoding="utf-8"),
        "functional": project.functional.read_text(encoding="utf-8"),
        "candidates": [
            {
                "name": candidate.name,
                "kind": candidate.kind,
                "expected_security": candidate.expected_security,
                "expected_behavior": candidate.expected_behavior,
                "note": candidate.note,
            }
            for candidate in project.candidates
        ],
        "isolation": ISOLATION_WARNING,
    }


def project_file(project: ProjectSpec, relative: str) -> str:
    name = safe_relative(relative, "file")
    path = (project.vulnerable / name).resolve()
    if not path.is_relative_to(project.vulnerable):
        raise ProjectError(f"file escapes the project: {relative!r}")
    if not path.is_file():
        raise ProjectError(f"file not found in project: {relative!r}")
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ProjectError(f"file is not UTF-8 text: {relative!r}") from exc


def project_candidate_files(project: ProjectSpec, name: str) -> dict[str, str]:
    candidate = next((item for item in project.candidates if item.name == name), None)
    if candidate is None:
        raise ProjectError(f"unknown project candidate: {name}")
    return load_candidate_overlay(project, name)


def project_run_record(result: ProjectResult) -> dict[str, object]:
    """Build the JSONL record for provenance and reproducibility."""

    return {
        "run_id": result.run_id,
        "project_id": result.project_id,
        "cwe": result.cwe,
        "input_mode": result.input_mode,
        "accepted": result.accepted,
        "rejected_by": result.rejected_by,
        "oracle_ok": result.oracle_ok,
        "security_pass": result.security_pass,
        "behavior_pass": result.behavior_pass,
        "checker_pass": result.checker_pass,
        "total_files": result.total_files,
        "total_lines": result.total_lines,
        "total_bytes": result.total_bytes,
        "overlay_files": result.overlay_files,
        "elapsed_ms": result.elapsed_ms,
        "isolation": result.isolation,
        "isolation_acknowledged": result.isolation_acknowledged,
        "provenance": result.provenance.model_dump(mode="json"),
        "reasons": result.reasons,
        "findings": [
            {
                "path": finding.path,
                "line": finding.line,
                "rule_id": finding.rule_id,
                "cwe": finding.cwe,
                "severity": finding.severity,
                "message": finding.message,
            }
            for finding in result.findings
        ],
    }
