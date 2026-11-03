"""Execution engine for the security worker pack."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Literal

from .checkers import BuiltinChecker, run_bandit
from .manifest import discover_tasks
from .models import (
    CandidateManifest,
    CandidateResult,
    CheckerResult,
    TaskResult,
    TaskSpec,
)

CheckerName = Literal["acv-rules", "bandit"]


def _run(command: list[str], cwd: Path, env: dict[str, str], timeout: int) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        return 124, f"{stdout}{stderr}\n[timeout after {timeout}s]"
    return proc.returncode, f"{proc.stdout}{proc.stderr}"


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
    rules = BuiltinChecker()
    return {
        "acv-rules": CheckerResult(
            tool="acv-rules",
            available=True,
            findings=rules.scan(candidate),
            version=rules.version,
        ),
        "bandit": run_bandit(candidate),
    }


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

    security_pass = poc_exit == 1
    behavior_pass = behavior_exit == 0
    checker_pass = primary.passed
    accepted = security_pass and behavior_pass and checker_pass
    expected_accepted = candidate.kind in {"gold", "benign"}

    reasons: list[str] = []
    if poc_exit == 0:
        reasons.append("PoC still succeeds")
    elif poc_exit != 1:
        reasons.append(f"PoC did not return a clean verdict (exit {poc_exit})")
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
    )


def _checker_summary(
    candidates: list[CandidateResult],
    vulnerable_checks: dict[str, CheckerResult],
    fixed_checks: dict[str, CheckerResult],
) -> dict[str, dict[str, float | int | str | bool]]:
    summary: dict[str, dict[str, float | int | str | bool]] = {}
    for name in ("acv-rules", "bandit"):
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
    return [run_task(task, primary_checker=primary_checker) for task in tasks]
