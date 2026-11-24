"""Tests for real-repository intake.

The network-dependent stages are covered by `acv repo-verify` against a live
clone. These tests pin the logic that decides a verdict, which is where a
silent false pass would come from.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from acv.models import CheckerResult, CheckFinding
from acv.repo_intake import RepoIntakeError, RepoSpec, apply_patch, new_findings
from acv.repo_tasks import load_repo_task
from acv.verdict import classify_poc


def finding(rule: str, message: str, path: str = "src/app.py") -> CheckFinding:
    return CheckFinding(rule_id=rule, cwe="CWE-79", severity="high", message=message, path=path)


def result(*findings: CheckFinding) -> CheckerResult:
    return CheckerResult(tool="acv-rules", available=True, findings=list(findings))


class TestDifferentialFindings:
    """A patch is judged on what it introduces, not on pre-existing code."""

    def test_preexisting_findings_do_not_block(self) -> None:
        baseline = {"acv-rules": result(finding("ACV004", "pickle loader"))}
        patched = {"acv-rules": result(finding("ACV004", "pickle loader"))}

        delta = new_findings(baseline, patched)

        assert delta["acv-rules"].findings == []
        assert delta["acv-rules"].passed

    def test_new_finding_blocks(self) -> None:
        baseline = {"acv-rules": result()}
        patched = {"acv-rules": result(finding("ACV001", "os.system call"))}

        delta = new_findings(baseline, patched)

        assert len(delta["acv-rules"].findings) == 1
        assert not delta["acv-rules"].passed

    def test_removed_finding_is_not_reintroduced(self) -> None:
        baseline = {"acv-rules": result(finding("ACV001", "os.system call"))}
        patched = {"acv-rules": result()}

        delta = new_findings(baseline, patched)

        assert delta["acv-rules"].findings == []

    def test_line_shift_is_not_a_new_finding(self) -> None:
        before = finding("ACV001", "os.system call")
        after = CheckFinding(
            rule_id="ACV001",
            cwe="CWE-78",
            severity="high",
            message="os.system call",
            line=99,
            path="src/app.py",
        )

        delta = new_findings({"acv-rules": result(before)}, {"acv-rules": result(after)})

        assert delta["acv-rules"].findings == []

    def test_missing_baseline_treats_everything_as_new(self) -> None:
        patched = {"acv-rules": result(finding("ACV001", "os.system call"))}

        delta = new_findings({}, patched)

        assert len(delta["acv-rules"].findings) == 1


class TestVerdictContract:
    """The gate must never read a crash as a blocked attack."""

    def test_crash_is_error(self) -> None:
        assert classify_poc(1, "Traceback (most recent call last):\n  ...") == "error"

    def test_clean_exit_one_is_blocked(self) -> None:
        assert classify_poc(1, "blocked: all payloads rejected") == "blocked"

    def test_reproduction_is_vulnerable(self) -> None:
        assert classify_poc(0, "exploit: injected") == "vulnerable"


class TestProtectedPaths:
    """A candidate may not edit the tests that judge it."""

    def test_task_json_is_loaded(self, tmp_path: Path) -> None:
        task = tmp_path / "task"
        (task / "poc").mkdir(parents=True)
        (task / "poc" / "exploit.py").write_text("print('x')\n", encoding="utf-8")
        (task / "task.json").write_text(
            '{"id": "demo", "title": "Demo task", "cwe": "CWE-79",'
            ' "repo_url": "https://example.invalid/r.git", "commit": "abc",'
            ' "functional": "repo:tests/test_x.py"}',
            encoding="utf-8",
        )

        spec = load_repo_task(task)

        assert spec.task_id == "demo"
        assert spec.functional_in_repo
        assert spec.functional_target(Path("/clone")) == Path("/clone/tests/test_x.py")

    def test_missing_poc_is_rejected(self, tmp_path: Path) -> None:
        task = tmp_path / "task"
        task.mkdir()
        (task / "task.json").write_text(
            '{"id": "demo", "title": "Demo task", "cwe": "CWE-79",'
            ' "repo_url": "https://example.invalid/r.git", "commit": "abc"}',
            encoding="utf-8",
        )

        with pytest.raises(RepoIntakeError, match="poc file does not exist"):
            load_repo_task(task)

    def test_missing_required_fields_are_rejected(self, tmp_path: Path) -> None:
        task = tmp_path / "task"
        task.mkdir()
        (task / "task.json").write_text('{"id": "demo"}', encoding="utf-8")

        with pytest.raises(RepoIntakeError, match="missing"):
            load_repo_task(task)


class TestApplyPatchGuard:
    """A diff that edits tests or evidence must be refused."""

    def _spec(self, task_dir: Path) -> RepoSpec:
        return RepoSpec(
            task_id="demo",
            title="Demo",
            cwe="CWE-79",
            summary="demo",
            repo_url="https://example.invalid/r.git",
            commit="abc",
            task_dir=task_dir,
        )

    def test_diff_touching_tests_is_refused(self, tmp_path: Path) -> None:
        tree = tmp_path / "tree"
        (tree / "tests").mkdir(parents=True)
        (tree / "tests" / "test_app.py").write_text("def test_a():\n    pass\n", encoding="utf-8")

        diff = (
            "--- a/tests/test_app.py\n"
            "+++ b/tests/test_app.py\n"
            "@@ -1,2 +1,2 @@\n"
            " def test_a():\n"
            "-    pass\n"
            "+    assert True\n"
        )

        with pytest.raises(RepoIntakeError, match="protected"):
            apply_patch(tree, diff, self._spec(tmp_path))
