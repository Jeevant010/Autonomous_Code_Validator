"""Check whether a known vulnerability is still present on a live default branch.

The pinned commit in a task record is a historical reproduction target. A pull
request is only useful if the vulnerability is still present *today*, so this
module clones the repository's current default branch and runs the same trusted
PoC against it.

The verdict is deliberately three-way. ``unfixed`` means the attack reproduced
on live code, which is the only state in which a contribution makes sense.
``fixed`` means the attack was blocked. ``unknown`` means the PoC could not run
at all, for example because the internal API it drives was renamed; that is not
evidence either way and must never be reported as a finding.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .projects import ISOLATION_WARNING
from .repo_intake import (
    RepoIntakeError,
    RepoSpec,
    _environment,
    _git,
    _prepare_scratch,
    _run_bootstrap,
    install_dependencies,
)
from .sandbox import SandboxPolicy
from .sandbox import run as run_sandboxed
from .verdict import classify_poc

StaleStatus = Literal["unfixed", "fixed", "unknown"]

DEFAULT_BRANCH_TIMEOUT = 300


@dataclass
class StaleReport:
    """Whether one known vulnerability still reproduces on live code."""

    task_id: str
    title: str
    cwe: str
    repo_url: str
    pinned_commit: str
    branch: str
    head_commit: str
    status: StaleStatus
    poc_exit: int
    poc_output: str
    detail: str
    elapsed_ms: int

    @property
    def is_live(self) -> bool:
        return self.status == "unfixed"


def default_branch(tree: Path) -> str:
    """Resolve the branch a repository actually develops on."""

    try:
        ref = _git(["symbolic-ref", "--short", "refs/remotes/origin/HEAD"], cwd=tree).strip()
        return ref.removeprefix("origin/")
    except RepoIntakeError:
        pass
    for candidate in ("main", "master"):
        try:
            _git(["rev-parse", "--verify", f"origin/{candidate}"], cwd=tree)
            return candidate
        except RepoIntakeError:
            continue
    raise RepoIntakeError("could not determine the default branch")


def probe_default_branch(
    spec: RepoSpec,
    *,
    branch: str = "",
    timeout: int = DEFAULT_BRANCH_TIMEOUT,
) -> StaleReport:
    """Clone the live default branch and run the trusted PoC against it."""

    started = time.perf_counter()
    tree = Path(tempfile.mkdtemp(prefix=f"acv-stale-{spec.task_id}-"))
    try:
        _git(
            ["clone", "--filter=blob:none", "--no-checkout", spec.repo_url, str(tree)],
            timeout=DEFAULT_BRANCH_TIMEOUT,
        )
        resolved = branch or default_branch(tree)
        _git(["checkout", "--quiet", "--detach", f"origin/{resolved}"], cwd=tree)
        head = _git(["rev-parse", "HEAD"], cwd=tree).strip()

        # Live code may need build-generated files, for example a version module
        # written by the packaging backend. The task declares how to recreate them.
        bootstrap_note = ""
        try:
            _run_bootstrap(spec, tree)
        except RepoIntakeError as exc:
            bootstrap_note = f"bootstrap failed: {str(exc).splitlines()[0]}"

        try:
            install_dependencies(spec, tree)
            install_note = ""
        except RepoIntakeError as exc:
            # The dependency set on the release may not match live requirements.
            # The PoC can still run if the package has no hard dependencies.
            install_note = f"dependency install failed: {str(exc).splitlines()[0]}"

        scratch = _prepare_scratch(tree)
        policy = SandboxPolicy(
            timeout=float(spec.poc_timeout),
            cpu_seconds=max(spec.poc_timeout, 1),
            memory_mb=spec.memory_mb,
            file_size_mb=64,
            max_output_bytes=1_000_000,
        )
        exit_code, output = run_sandboxed(
            [sys.executable, str(spec.poc_path)],
            cwd=tree,
            env=_environment(spec, tree),
            policy=policy,
            scratch_dir=scratch,
        )
    finally:
        shutil.rmtree(tree, ignore_errors=True)

    raw = classify_poc(exit_code, output)
    mapping: dict[str, StaleStatus] = {
        "vulnerable": "unfixed",
        "blocked": "fixed",
        "error": "unknown",
    }
    status = mapping[raw]

    detail = {
        "unfixed": "the attack reproduced on live code",
        "fixed": "the attack was blocked on live code",
        "unknown": "the PoC could not reach a verdict on live code",
    }[status]
    if status == "unknown":
        first_error = next(
            (line for line in output.splitlines() if "Error" in line or "error:" in line),
            output.strip().splitlines()[0] if output.strip() else "",
        )
        if first_error:
            detail += f": {first_error[:200]}"
    if bootstrap_note:
        detail += f" ({bootstrap_note})"
    if install_note:
        detail += f" ({install_note})"

    return StaleReport(
        task_id=spec.task_id,
        title=spec.title,
        cwe=spec.cwe,
        repo_url=spec.repo_url,
        pinned_commit=spec.commit,
        branch=resolved,
        head_commit=head,
        status=status,
        poc_exit=exit_code,
        poc_output=output.strip()[-1500:],
        detail=detail,
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


ISOLATION = ISOLATION_WARNING
