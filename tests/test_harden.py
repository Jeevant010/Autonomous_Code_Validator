"""Tests for the hardening-branch builder.

The builder's most important property is refusal. An unattended process that
produces a branch for an already-fixed vulnerability wastes a maintainer's time,
so refusal must be the default and must be tested.
"""

from __future__ import annotations

from pathlib import Path

from acv.harden import GateEvidence, HardenReport, _is_evidence_path, pull_request_body
from acv.repo_intake import RepoSpec
from acv.stale import StaleReport


def spec() -> RepoSpec:
    return RepoSpec(
        task_id="demo",
        title="Demo",
        cwe="CWE-79",
        summary="demo",
        repo_url="https://github.com/example/demo.git",
        commit="a" * 40,
        task_dir=Path("/tmp/demo-task"),
    )


def stale(status: str, poc_output: str = "blocked: all payloads rejected") -> StaleReport:
    return StaleReport(
        task_id="demo",
        title="Demo",
        cwe="CWE-79",
        repo_url="https://github.com/example/demo.git",
        pinned_commit="a" * 40,
        branch="main",
        head_commit="b" * 40,
        status=status,  # type: ignore[arg-type]
        poc_exit=1,
        poc_output=poc_output,
        detail="",
        elapsed_ms=0,
    )


def gate() -> GateEvidence:
    return GateEvidence(
        changed_files=["src/app.py"],
        attack="blocked",
        attack_output="blocked",
        behavior="pass",
        behavior_output="1 passed",
        checker="not run for a live branch",
    )


class TestPullRequestBody:
    def test_fixed_vulnerability_is_never_called_live(self) -> None:
        body = pull_request_body(spec(), stale("fixed"), gate())

        assert "already fixed" in body
        assert "not a claim that the vulnerability is live" in body
        assert "still reproduces" not in body

    def test_live_vulnerability_is_described_as_live(self) -> None:
        body = pull_request_body(spec(), stale("unfixed", "exploit: injected"), gate())

        assert "reproduces on `main`" in body
        assert "exploit: injected" in body

    def test_evidence_table_is_present(self) -> None:
        body = pull_request_body(spec(), stale("unfixed"), gate())

        assert "Attack after this patch | blocked" in body
        assert "test suite | pass" in body

    def test_no_absolute_paths_leak_into_the_body(self) -> None:
        body = pull_request_body(spec(), stale("unfixed"), gate())

        assert "/tmp/" not in body


class TestEvidencePaths:
    def test_tests_directory_is_protected(self) -> None:
        assert _is_evidence_path("tests/test_app.py")
        assert _is_evidence_path("src/tests/conftest.py")

    def test_configuration_is_protected(self) -> None:
        assert _is_evidence_path("pyproject.toml")
        assert _is_evidence_path("setup.cfg")
        assert _is_evidence_path("conftest.py")

    def test_source_is_not_protected(self) -> None:
        assert not _is_evidence_path("src/app.py")
        assert not _is_evidence_path("requests/sessions.py")


class TestReport:
    def test_ready_only_when_status_is_ready(self) -> None:
        base = dict(
            task_id="demo",
            title="Demo",
            cwe="CWE-79",
            repo_url="https://github.com/example/demo.git",
            branch="acv/harden-1",
            clone_dir="/tmp/demo",
            commit="b" * 40,
            changed_files=["src/app.py"],
        )

        assert HardenReport(status="ready", **base).ready  # type: ignore[arg-type]
        assert not HardenReport(status="refused", **base).ready  # type: ignore[arg-type]


class TestRefusalNeedsNoNetwork:
    """These assert the guard logic without cloning anything."""

    def test_unknown_status_is_not_treated_as_live(self) -> None:
        report = stale("unknown", "error: cannot import")

        assert not report.is_live

    def test_fixed_status_is_not_live(self) -> None:
        assert not stale("fixed").is_live

    def test_unfixed_status_is_the_only_live_one(self) -> None:
        assert stale("unfixed").is_live
        assert [s for s in ("fixed", "unknown") if stale(s).is_live] == []
