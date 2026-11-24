"""Tests for the real-repository benchmark reporting.

The dashboard is the artifact a reviewer reads, so a wrong colour or a missing
row is a real defect, not cosmetics.
"""

from __future__ import annotations

from acv.repo_report import render_dashboard


def payload() -> dict[str, object]:
    return {
        "generated_at": "2026-01-01T00:00:00Z",
        "totals": {
            "tasks": 1,
            "cases": 2,
            "agreements": 2,
            "disagreements": 0,
            "false_accepts": 0,
            "false_rejects": 0,
            "accepted": 1,
            "rejected": 1,
        },
        "tasks": [
            {
                "task": "demo_task",
                "title": "Demo",
                "cwe": "CWE-79",
                "repo_url": "https://github.com/example/demo.git",
                "commit": "abcdef1234567890",
                "cases": {
                    "baseline": {
                        "verdict": "REJECT",
                        "expected": "REJECT",
                        "ok": True,
                        "rejected_by": "poc",
                        "oracle": "vulnerable",
                        "poc": "vulnerable",
                        "behavior_exit": 0,
                        "changed": [],
                        "files": 10,
                        "lines": 500,
                    },
                    "upstream fix": {
                        "verdict": "ACCEPT",
                        "expected": "ACCEPT",
                        "ok": True,
                        "rejected_by": "none",
                        "oracle": "vulnerable",
                        "poc": "blocked",
                        "behavior_exit": 0,
                        "changed": ["src/app.py"],
                        "files": 10,
                        "lines": 505,
                    },
                },
            }
        ],
    }


class TestDashboard:
    def test_rejects_are_red_and_accepts_are_green(self) -> None:
        html = render_dashboard(payload())

        assert html.count("class='pill ok'") == 1
        assert html.count("class='pill bad'") == 1

    def test_every_case_renders(self) -> None:
        html = render_dashboard(payload())

        assert "baseline" in html
        assert "upstream fix" in html
        assert html.count("<tr>") >= 3  # header plus two rows

    def test_failure_is_explained_in_words(self) -> None:
        html = render_dashboard(payload())

        assert "the attack still worked" in html
        assert "attack blocked, tests pass" in html

    def test_no_unexplained_jargon_in_verdict_cell(self) -> None:
        html = render_dashboard(payload())

        # The verdict cell must state the expectation, not just a bare code.
        assert "expected REJECT" in html
        assert "expected ACCEPT" in html

    def test_escapes_task_input(self) -> None:
        bad = payload()
        bad["tasks"][0]["task"] = "<script>alert(1)</script>"  # type: ignore[index]

        html = render_dashboard(bad)

        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_error_rows_are_reported_not_dropped(self) -> None:
        bad = payload()
        bad["tasks"].append({"task": "broken", "cwe": "CWE-1", "error": "clone failed"})

        html = render_dashboard(bad)

        assert "broken" in html
        assert "clone failed" in html
