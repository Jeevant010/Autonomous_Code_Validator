"""Execution engine for the security worker pack."""

from __future__ import annotations

import difflib
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Literal

from .checkers import CheckerAdapter, checker_adapters
from .manifest import discover_tasks
from .models import (
    CandidateManifest,
    CandidateResult,
    CheckerResult,
    SourceResult,
    TaskResult,
    TaskSpec,
)
from .sandbox import SandboxPolicy
from .sandbox import run as run_sandboxed
from .verdict import classify_poc

CheckerName = Literal["acv-rules", "bandit", "semgrep"]


def _run(command: list[str], cwd: Path, env: dict[str, str], timeout: int) -> tuple[int, str]:
    policy = SandboxPolicy(
        timeout=float(timeout),
        cpu_seconds=max(timeout, 1),
        memory_mb=512,
        file_size_mb=16,
    )
    return run_sandboxed(command, cwd=cwd, env=env, policy=policy)


def _environment(task: TaskSpec, workdir: Path) -> dict[str, str]:
    env = os.environ.copy()
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(workdir) + (os.pathsep + existing if existing else "")
    env["ACV_DATA_DIR"] = str(task.data_dir)
    env["ACV_TASK_ID"] = task.task_id
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONHASHSEED"] = "0"
    env["NO_PROXY"] = "*"
    env["no_proxy"] = "*"
    return env


def _candidate_directory(candidate: Path) -> tempfile.TemporaryDirectory[str]:
    temp = tempfile.TemporaryDirectory(prefix="acv-candidate-")
    shutil.copyfile(candidate, Path(temp.name) / "worker.py")
    return temp


def run_poc(task: TaskSpec, candidate: Path, timeout: int = 30) -> tuple[int, str]:
    with _candidate_directory(candidate) as workdir:
        env = _environment(task, Path(workdir))
        return _run([sys.executable, str(task.poc)], cwd=task.root, env=env, timeout=timeout)


def run_functional(task: TaskSpec, candidate: Path, timeout: int = 60) -> tuple[int, str]:
    with _candidate_directory(candidate) as workdir:
        env = _environment(task, Path(workdir))
        return _run(
            [
                sys.executable,
                "-m",
                "pytest",
                str(task.functional),
                "-q",
                "-p",
                "no:cacheprovider",
            ],
            cwd=task.root,
            env=env,
            timeout=timeout,
        )


def run_checkers(candidate: Path) -> dict[str, CheckerResult]:
    adapters: tuple[CheckerAdapter, ...] = checker_adapters()
    return {adapter.name: adapter.run(candidate) for adapter in adapters}


def evaluate_candidate(
    task: TaskSpec,
    candidate: CandidateManifest,
    primary_checker: CheckerName = "acv-rules",
) -> CandidateResult:
    path = (task.root / candidate.path).resolve()
    poc_exit, poc_output = run_poc(task, path)
    behavior_exit, behavior_output = run_functional(task, path)
    checker_results = run_checkers(path)

    primary = checker_results.get(primary_checker)
    if primary is None or not primary.available:
        primary = checker_results["acv-rules"]
        primary_checker = "acv-rules"

    poc_verdict = classify_poc(poc_exit, poc_output)
    security_pass = poc_verdict == "blocked"
    behavior_pass = behavior_exit == 0
    checker_pass = primary.passed
    accepted = security_pass and behavior_pass and checker_pass
    expected_accepted = candidate.kind in {"gold", "benign"}

    reasons: list[str] = []
    if poc_verdict == "vulnerable":
        reasons.append("PoC still succeeds")
    elif poc_verdict == "error":
        reasons.append("PoC could not reach a verdict: the candidate crashed or the fixture broke")
    if behavior_exit != 0:
        reasons.append("functional suite fails")
    if not checker_pass:
        ids = ", ".join(sorted({finding.rule_id for finding in primary.blocking}))
        reasons.append(f"checker findings: {ids or 'unavailable'}")
    if accepted and candidate.kind == "mutant":
        reasons.append("accepted known-bad variant")

    return CandidateResult(
        task_id=task.task_id,
        task_title=task.title,
        cwe=task.cwe,
        name=candidate.name,
        kind=candidate.kind,
        expected_security=candidate.expected_security,
        expected_behavior=candidate.expected_behavior,
        poc_exit=poc_exit,
        behavior_exit=behavior_exit,
        poc_output=poc_output.strip()[-1200:],
        behavior_output=behavior_output.strip()[-1200:],
        security_pass=security_pass,
        behavior_pass=behavior_pass,
        checker_pass=checker_pass,
        accepted=accepted,
        expected_accepted=expected_accepted,
        correct=accepted == expected_accepted,
        reasons=reasons,
        findings=primary.findings,
        checker_tool=primary.tool if primary.available else "acv-rules",
        checker_results=checker_results,
        poc_verdict=poc_verdict,
    )


class PatchApplyError(ValueError):
    """Raised when a supplied unified diff cannot be applied safely."""


def _validate_worker_diff(diff: str) -> None:
    if not diff.strip():
        raise PatchApplyError("diff is empty")
    targets: set[str] = set()
    for line in diff.splitlines():
        if not line.startswith(("--- ", "+++ ")):
            continue
        raw = line[4:].split("\t", 1)[0].strip()
        if raw == "/dev/null":
            continue
        path = PurePosixPath(raw)
        if ".." in path.parts:
            raise PatchApplyError("diff paths may not escape the work directory")
        normalized = raw.removeprefix("a/").removeprefix("b/")
        if normalized != "worker.py":
            raise PatchApplyError("diff may only modify worker.py")
        targets.add(normalized)
    if not targets:
        raise PatchApplyError("diff has no worker.py target")


def _apply_worker_diff(task: TaskSpec, diff: str, workdir: Path) -> Path:
    candidate = workdir / "worker.py"
    candidate.write_text(task.vulnerable.read_text(encoding="utf-8"), encoding="utf-8")
    diff_path = workdir / "change.diff"
    diff_path.write_text(diff, encoding="utf-8")

    for command in (
        ["git", "apply", "--check", "-p1", "change.diff"],
        ["git", "apply", "-p1", "change.diff"],
    ):
        try:
            proc = subprocess.run(
                command,
                cwd=workdir,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PatchApplyError(f"could not run git apply: {exc}") from exc
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip()
            raise PatchApplyError(f"diff did not apply: {detail or 'git apply failed'}")
    return candidate


def _evaluate_source_path(
    task: TaskSpec,
    candidate: Path,
    primary_checker: CheckerName,
    started: float,
    *,
    diff_applied: bool,
    input_mode: str,
) -> SourceResult:
    oracle_exit, oracle_output = run_poc(task, task.vulnerable)
    oracle_ok = oracle_exit == 0

    candidate_code = candidate.read_text(encoding="utf-8")
    vulnerable_code = task.vulnerable.read_text(encoding="utf-8")
    applied_diff = "".join(
        difflib.unified_diff(
            vulnerable_code.splitlines(keepends=True),
            candidate_code.splitlines(keepends=True),
            fromfile="a/worker.py",
            tofile="b/worker.py",
        )
    )

    poc_exit, poc_output = run_poc(task, candidate)
    behavior_exit, behavior_output = run_functional(task, candidate)
    checker_results = run_checkers(candidate)

    primary = checker_results.get(primary_checker)
    if primary is None or not primary.available:
        primary = checker_results["acv-rules"]
        primary_checker = "acv-rules"

    poc_verdict = classify_poc(poc_exit, poc_output)
    security_pass = poc_verdict == "blocked"
    behavior_pass = behavior_exit == 0
    checker_pass = primary.passed
    accepted = oracle_ok and security_pass and behavior_pass and checker_pass

    reasons: list[str] = []
    if not oracle_ok:
        reasons.append(
            f"oracle did not reproduce on the vulnerable source (exit {oracle_exit})"
        )
    if poc_verdict == "vulnerable":
        reasons.append("PoC still succeeds")
    elif poc_verdict == "error":
        reasons.append("PoC could not reach a verdict: the candidate crashed or the fixture broke")
    if behavior_exit != 0:
        reasons.append("functional suite fails")
    if not checker_pass:
        ids = ", ".join(sorted({finding.rule_id for finding in primary.blocking}))
        reasons.append(f"checker findings: {ids or 'unavailable'}")

    return SourceResult(
        task_id=task.task_id,
        task_title=task.title,
        cwe=task.cwe,
        poc_exit=poc_exit,
        behavior_exit=behavior_exit,
        poc_output=poc_output.strip()[-1200:],
        behavior_output=behavior_output.strip()[-1200:],
        security_pass=security_pass,
        behavior_pass=behavior_pass,
        checker_pass=checker_pass,
        accepted=accepted,
        reasons=reasons,
        findings=primary.findings,
        checker_tool=primary.tool if primary.available else "acv-rules",
        checker_results=checker_results,
        elapsed_ms=int((time.perf_counter() - started) * 1000),
        poc_verdict=poc_verdict,
        oracle_exit=oracle_exit,
        oracle_output=oracle_output.strip()[-1200:],
        oracle_ok=oracle_ok,
        diff_applied=diff_applied,
        input_mode=input_mode,
        candidate_code=candidate_code,
        applied_diff=applied_diff,
    )


def evaluate_source(
    task: TaskSpec,
    code: str,
    primary_checker: CheckerName = "acv-rules",
) -> SourceResult:
    """Run the same gate against source supplied at runtime.

    There is no expected label here: the result says whether the supplied code
    passes the executable oracle and the checker, not whether it is the "gold"
    answer. This is the primitive behind a paste-in patch lab.
    """

    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="acv-source-") as workdir:
        candidate = Path(workdir) / "worker.py"
        candidate.write_text(code, encoding="utf-8")
        return _evaluate_source_path(
            task,
            candidate,
            primary_checker,
            started,
            diff_applied=False,
            input_mode="source",
        )


def evaluate_patch(
    task: TaskSpec,
    diff: str,
    primary_checker: CheckerName = "acv-rules",
) -> SourceResult:
    """Apply a unified diff to the vulnerable source and run the same gate."""

    started = time.perf_counter()
    _validate_worker_diff(diff)
    with tempfile.TemporaryDirectory(prefix="acv-patch-") as workdir:
        candidate = _apply_worker_diff(task, diff, Path(workdir))
        return _evaluate_source_path(
            task,
            candidate,
            primary_checker,
            started,
            diff_applied=True,
            input_mode="diff",
        )


def _checker_summary(
    candidates: list[CandidateResult],
    vulnerable_checks: dict[str, CheckerResult],
    fixed_checks: dict[str, CheckerResult],
) -> dict[str, dict[str, float | int | str | bool]]:
    summary: dict[str, dict[str, float | int | str | bool]] = {}
    for name in vulnerable_checks:
        vulnerable = vulnerable_checks.get(name)
        fixed = fixed_checks.get(name)
        if vulnerable is None or fixed is None:
            continue
        mutants = [candidate for candidate in candidates if candidate.kind == "mutant"]
        safe = [candidate for candidate in candidates if candidate.kind in {"gold", "benign"}]

        recall_hits = int(bool(vulnerable.blocking)) + sum(
            1
            for candidate in mutants
            if candidate.checker_results.get(name)
            and bool(candidate.checker_results[name].blocking)
        )
        recall_den = 1 + len(mutants)
        precision_hits = int(not fixed.blocking) + sum(
            1
            for candidate in safe
            if candidate.checker_results.get(name) and not candidate.checker_results[name].blocking
        )
        precision_den = 1 + len(safe)
        missed_mutants = sum(
            1
            for candidate in mutants
            if candidate.checker_results.get(name) and not candidate.checker_results[name].blocking
        )
        summary[name] = {
            "available": vulnerable.available and fixed.available,
            "version": vulnerable.version or "unknown",
            "recall": round(recall_hits / recall_den, 4) if recall_den else 0.0,
            "precision": round(precision_hits / precision_den, 4) if precision_den else 0.0,
            "false_repair": round(missed_mutants / len(mutants), 4) if mutants else 0.0,
            "recall_hits": recall_hits,
            "recall_total": recall_den,
            "precision_hits": precision_hits,
            "precision_total": precision_den,
            "missed_mutants": missed_mutants,
            "mutants": len(mutants),
        }
    return summary


def run_task(task: TaskSpec, primary_checker: CheckerName = "acv-rules") -> TaskResult:
    vulnerable_poc_exit, _ = run_poc(task, task.vulnerable)
    fixed_poc_exit, _ = run_poc(task, task.fixed)
    fixed_behavior_exit, _ = run_functional(task, task.fixed)
    baseline_ok = vulnerable_poc_exit == 0 and fixed_poc_exit == 1 and fixed_behavior_exit == 0

    candidates = [
        evaluate_candidate(task, candidate, primary_checker=primary_checker)
        for candidate in task.candidates
    ]

    vulnerable_checks = run_checkers(task.vulnerable)
    fixed_checks = run_checkers(task.fixed)

    return TaskResult(
        task_id=task.task_id,
        title=task.title,
        cwe=task.cwe,
        summary=task.summary,
        tags=task.tags,
        vulnerable_poc_exit=vulnerable_poc_exit,
        fixed_poc_exit=fixed_poc_exit,
        fixed_behavior_exit=fixed_behavior_exit,
        baseline_ok=baseline_ok,
        candidates=candidates,
        checker_summary=_checker_summary(candidates, vulnerable_checks, fixed_checks),
    )


def run_audit(
    pack_root: Path,
    primary_checker: CheckerName = "acv-rules",
    task_ids: set[str] | None = None,
) -> list[TaskResult]:
    tasks = discover_tasks(pack_root)
    if task_ids:
        tasks = [task for task in tasks if task.task_id in task_ids]
    return run_audit_tasks(tasks, primary_checker=primary_checker)


def run_audit_tasks(
    tasks: list[TaskSpec],
    primary_checker: CheckerName = "acv-rules",
) -> list[TaskResult]:
    """Run the two-sided audit over an already discovered task list."""

    return [run_task(task, primary_checker=primary_checker) for task in tasks]
