"""Build a reviewable hardening branch for a live vulnerability.

This is deliberately the last step, not the first. A branch is only produced
when the vulnerability still reproduces on the repository's default branch AND
the patch passes every gate signal. If the attack is already blocked upstream,
the builder refuses and says so, because a pull request for an already-fixed
CVE is noise that a maintainer closes.

Nothing is published. The output is:

* a local git branch in a clone the caller keeps, and
* a pull-request body written to a file for the caller to review.

Pushing, opening a pull request, or touching a remote needs a separate,
explicit action by a human with the credentials. That is not an oversight: an
unattended process that opens pull requests against third-party projects is
spam by definition, and no amount of automation makes it a contribution.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

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
from .stale import StaleReport, probe_default_branch
from .verdict import classify_poc

BRANCH_PREFIX = "acv/harden-"


class HardenRefused(RuntimeError):
    """Raised when a branch must not be built, with the reason."""


@dataclass
class GateEvidence:
    """The four signals recorded for one built branch."""

    changed_files: list[str]
    attack: str
    attack_output: str
    behavior: str
    behavior_output: str
    checker: str


@dataclass
class HardenReport:
    """The outcome of building one hardening branch."""

    task_id: str
    title: str
    cwe: str
    repo_url: str
    status: str
    branch: str
    clone_dir: str
    commit: str
    changed_files: list[str]
    gate: GateEvidence | None = None
    pull_request_body: str = ""
    pull_request_path: str = ""
    notes: list[str] = field(default_factory=list)
    elapsed_ms: int = 0

    @property
    def ready(self) -> bool:
        return self.status == "ready"


def _run(spec: RepoSpec, tree: Path, command: list[str], timeout: int) -> tuple[int, str]:
    scratch = _prepare_scratch(tree)
    policy = SandboxPolicy(
        timeout=float(timeout),
        cpu_seconds=max(timeout, 1),
        memory_mb=spec.memory_mb,
        file_size_mb=64,
        max_output_bytes=2_000_000,
    )
    return run_sandboxed(
        command,
        cwd=tree,
        env=_environment(spec, tree),
        policy=policy,
        scratch_dir=scratch,
    )


def pull_request_body(spec: RepoSpec, report: StaleReport, gate: GateEvidence) -> str:
    """Write the pull-request description a maintainer would actually read.

    The text must never claim a vulnerability is live when it is not. When the
    probe found current code already safe, the body says so and frames the change
    as further hardening, never as a fix.
    """

    first_line = next(
        (line for line in report.poc_output.splitlines() if line.strip()),
        "(no output)",
    )

    if report.status == "unfixed":
        opening = (
            f"This change hardens `{spec.repo_url}` against **{spec.cwe}**.\n\n"
            f"The weakness reproduces on `{report.branch}` at "
            f"`{report.head_commit[:12]}`:\n\n"
            f"```\n{first_line}\n```\n\n"
            "After this patch the same attack is blocked and the repository's own "
            "test suite still passes."
        )
        original = "reproduces (vulnerable)"
    else:
        opening = (
            f"This change adds further hardening against **{spec.cwe}** in "
            f"`{spec.repo_url}`.\n\n"
            f"The reported weakness is **already fixed** on `{report.branch}` at "
            f"`{report.head_commit[:12]}`: the attack used here is rejected on "
            "current code.\n\n"
            "This branch is therefore **not a claim that the vulnerability is "
            "live**. It either tightens the existing guard or adds a regression "
            "test, so the behaviour cannot silently regress."
        )
        original = "blocked (already safe)"

    return f"""## Summary

{opening}

## What this patch changes

{chr(10).join(f"- `{path}`" for path in gate.changed_files) or "- (see diff)"}

## How it was verified

Every check below ran against a clean clone of `{report.branch}`, not against a
fixture. The attack script lives outside the repository, so a patch cannot edit
the evidence that judges it.

| Check | Result |
| :--- | :--- |
| Attack on the original code | {original} |
| Attack after this patch | {gate.attack} |
| Repository's own test suite | {gate.behavior} |
| New static findings versus baseline | {gate.checker} |

## Reproducing

```
git clone {spec.repo_url}
# apply this branch, then run the attack recorded by the task
```

Functional behaviour was checked with the repository's own tests.

---

*Prepared with an executable-evidence verifier. The gate, not the author,
decided that the checks above pass.*
"""


def build_hardening_branch(
    spec: RepoSpec,
    *,
    diff: str,
    clone_dir: Path | None = None,
    force: bool = False,
) -> HardenReport:
    """Build a branch only when the vulnerability is live and the patch passes.

    ``force`` does not bypass the gate. It only allows building a branch when the
    live probe says ``fixed``, which is useful for writing regression tests for a
    vulnerability that was recently patched.
    """

    started = time.perf_counter()
    notes: list[str] = []

    live = probe_default_branch(spec)
    if live.status == "unknown" and not force:
        raise HardenRefused(
            f"cannot tell whether {spec.task_id} is live ({live.detail}); "
            "refusing to build a contribution on unknown status. Use --force to "
            "build anyway and read the notes."
        )
    if live.status == "fixed" and not force:
        raise HardenRefused(
            f"{spec.task_id} is already fixed on {live.branch} at "
            f"{live.head_commit[:12]}. A pull request for an already-fixed issue "
            "would be closed and would count against the sender. Use --force only "
            "to write a regression test, never to claim a fix."
        )
    if live.status != "unfixed":
        notes.append(f"live status is {live.status}, not unfixed")

    if not diff.strip():
        raise HardenRefused("no patch was supplied; there is nothing to build")

    tree = clone_dir or Path(f"/tmp/acv-harden-{spec.task_id}")
    if (tree / ".git").exists():
        notes.append(f"reusing existing clone at {tree}")
    else:
        _git(
            ["clone", "--filter=blob:none", "--no-checkout", spec.repo_url, str(tree)],
            timeout=600,
        )
    _git(["checkout", "--quiet", "--detach", f"origin/{live.branch}"], cwd=tree)
    _run_bootstrap(spec, tree)
    try:
        install_dependencies(spec, tree)
    except RepoIntakeError as exc:
        notes.append(f"dependency install skipped: {str(exc).splitlines()[0]}")

    branch = f"{BRANCH_PREFIX}{spec.cwe.lower()}-{live.head_commit[:8]}"
    _git(["checkout", "--quiet", "-B", branch], cwd=tree)

    apply = subprocess.run(
        ["git", "apply", "-p1", "-"],
        cwd=tree,
        input=diff,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if apply.returncode != 0:
        detail = (apply.stderr or apply.stdout).strip()[:600]
        raise HardenRefused(f"the patch does not apply to {live.branch}: {detail}")

    changed = _git(["diff", "--name-only", "HEAD"], cwd=tree).split()
    if not changed:
        raise HardenRefused("the patch produced no change against live code")

    blocked_paths = [path for path in changed if _is_evidence_path(path)]
    if blocked_paths:
        raise HardenRefused(
            "the patch touches test or evidence paths: " + ", ".join(blocked_paths)
        )

    exit_code, output = _run(spec, tree, [_python(), str(spec.poc_path)], spec.poc_timeout)
    poc_verdict = classify_poc(exit_code, output)
    behavior_exit, behavior_output = _run(
        spec,
        tree,
        [_python(), "-m", "pytest", str(spec.functional_target(tree)), "-q"],
        spec.test_timeout,
    )

    gate = GateEvidence(
        changed_files=changed,
        attack=poc_verdict,
        attack_output=output.strip()[-1200:],
        behavior="pass" if behavior_exit == 0 else "fail",
        behavior_output=behavior_output.strip()[-1200:],
        checker="not run for a live branch",
    )

    if poc_verdict != "blocked":
        raise HardenRefused(
            f"the patch does not block the attack on live code (verdict {poc_verdict}); "
            "refusing to produce a branch"
        )
    if behavior_exit != 0:
        raise HardenRefused(
            "the patch breaks the repository's own tests; refusing to produce a branch"
        )

    commit = _git(["rev-parse", "HEAD"], cwd=tree).strip()
    body = pull_request_body(spec, live, gate)
    body_path = tree / "ACV_PULL_REQUEST.md"
    body_path.write_text(body, encoding="utf-8")

    return HardenReport(
        task_id=spec.task_id,
        title=spec.title,
        cwe=spec.cwe,
        repo_url=spec.repo_url,
        status="ready",
        branch=branch,
        clone_dir=str(tree),
        commit=commit,
        changed_files=changed,
        gate=gate,
        pull_request_body=body,
        pull_request_path=str(body_path),
        notes=notes,
        elapsed_ms=int((time.perf_counter() - started) * 1000),
    )


def _python() -> str:
    import sys

    return sys.executable


_PROTECTED = {"conftest.py", "pytest.ini", "tox.ini", "setup.cfg", "pyproject.toml"}


def _is_evidence_path(path: str) -> bool:
    parts = Path(path).parts
    if any(part in {"tests", "test"} for part in parts):
        return True
    return Path(path).name in _PROTECTED
