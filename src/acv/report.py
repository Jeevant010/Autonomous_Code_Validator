"""Aggregate audit results and render the human-facing outputs."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .models import CandidateResult, TaskResult


def _candidate_rows(results: list[TaskResult]) -> list[CandidateResult]:
    return [candidate for task in results for candidate in task.candidates]


def aggregate(results: list[TaskResult]) -> dict[str, Any]:
    candidates = _candidate_rows(results)
    gold = [candidate for candidate in candidates if candidate.kind == "gold"]
    benign = [candidate for candidate in candidates if candidate.kind == "benign"]
    mutants = [candidate for candidate in candidates if candidate.kind == "mutant"]
    false_passes = [candidate for candidate in mutants if candidate.accepted]
    false_rejections = [
        candidate
        for candidate in candidates
        if candidate.kind in {"gold", "benign"} and not candidate.accepted
    ]
    correct = sum(1 for candidate in candidates if candidate.correct)

    matrix = Counter(
        (
            "security_pass" if candidate.security_pass else "security_fail",
            "behavior_pass" if candidate.behavior_pass else "behavior_fail",
        )
        for candidate in candidates
    )

    checker_totals: dict[str, dict[str, Any]] = {}
    for task in results:
        for name, stats in task.checker_summary.items():
            bucket = checker_totals.setdefault(
                name,
                {
                    "name": name,
                    "version": stats.get("version", "unknown"),
                    "available": stats.get("available", False),
                    "recall_hits": 0,
                    "recall_total": 0,
                    "precision_hits": 0,
                    "precision_total": 0,
                    "missed_mutants": 0,
                    "mutants": 0,
                },
            )
            bucket["recall_hits"] += int(stats.get("recall_hits", 0))
            bucket["recall_total"] += int(stats.get("recall_total", 0))
            bucket["precision_hits"] += int(stats.get("precision_hits", 0))
            bucket["precision_total"] += int(stats.get("precision_total", 0))
            bucket["missed_mutants"] += int(stats.get("missed_mutants", 0))
            bucket["mutants"] += int(stats.get("mutants", 0))

    checker_comparison: list[dict[str, Any]] = []
    for bucket in checker_totals.values():
        recall_total = bucket["recall_total"]
        precision_total = bucket["precision_total"]
        mutant_count = bucket["mutants"]
        checker_comparison.append(
            {
                "name": bucket["name"],
                "version": bucket["version"],
                "available": bucket["available"],
                "recall": round(bucket["recall_hits"] / recall_total, 4) if recall_total else 0.0,
                "recall_hits": bucket["recall_hits"],
                "recall_total": recall_total,
                "precision": round(bucket["precision_hits"] / precision_total, 4)
                if precision_total
                else 0.0,
                "precision_hits": bucket["precision_hits"],
                "precision_total": precision_total,
                "false_repair": round(bucket["missed_mutants"] / mutant_count, 4)
                if mutant_count
                else 0.0,
                "missed_mutants": bucket["missed_mutants"],
                "mutants": mutant_count,
            }
        )
    checker_comparison.sort(key=lambda row: (-row["recall"], row["name"]))

    return {
        "tasks": len(results),
        "cwe_families": len({task.cwe for task in results}),
        "baseline_ok": sum(1 for task in results if task.baseline_ok),
        "baseline_failures": [task.task_id for task in results if not task.baseline_ok],
        "candidates": len(candidates),
        "gold": len(gold),
        "gold_accepted": sum(1 for candidate in gold if candidate.accepted),
        "benign": len(benign),
        "benign_accepted": sum(1 for candidate in benign if candidate.accepted),
        "mutants": len(mutants),
        "mutants_rejected": sum(1 for candidate in mutants if not candidate.accepted),
        "false_passes": len(false_passes),
        "false_rejections": len(false_rejections),
        "correct_verdicts": correct,
        "verdict_accuracy": round(correct / len(candidates), 4) if candidates else 0.0,
        "matrix": {
            "security_pass_behavior_pass": matrix[("security_pass", "behavior_pass")],
            "security_pass_behavior_fail": matrix[("security_pass", "behavior_fail")],
            "security_fail_behavior_pass": matrix[("security_fail", "behavior_pass")],
            "security_fail_behavior_fail": matrix[("security_fail", "behavior_fail")],
        },
        "checkers": checker_comparison,
        "false_pass_ids": [f"{c.task_id}/{c.name}" for c in false_passes],
        "false_rejection_ids": [f"{c.task_id}/{c.name}" for c in false_rejections],
    }


def _result_dicts(results: list[TaskResult]) -> list[dict[str, Any]]:
    return [asdict(result) for result in results]


def build_payload(results: list[TaskResult]) -> dict[str, Any]:
    summary = aggregate(results)
    return {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "product": "Autonomous Code Validator",
        "version": __version__,
        "summary": summary,
        "tasks": _result_dicts(results),
    }


def write_json(path: Path, results: list[TaskResult]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_payload(results), indent=2) + "\n", encoding="utf-8")
    return path


def write_presentation_data(path: Path, results: list[TaskResult]) -> Path:
    payload = build_payload(results)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "// Generated by acv audit. Do not edit by hand.\n"
        "window.ACV_DATA = " + json.dumps(payload, indent=2) + ";\n",
        encoding="utf-8",
    )
    return path


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def write_markdown(path: Path, results: list[TaskResult]) -> Path:
    summary = aggregate(results)
    lines = [
        "# Autonomous Code Validator: Audit Report",
        "",
        f"Generated: `{datetime.now(UTC).isoformat(timespec='seconds')}`",
        "",
        "## Headline",
        "",
        "| Measure | Value |",
        "| :--- | ---: |",
        f"| Security tasks | {summary['tasks']} |",
        f"| CWE families | {summary['cwe_families']} |",
        f"| Baseline reproduced | {summary['baseline_ok']} / {summary['tasks']} |",
        f"| Candidates evaluated | {summary['candidates']} |",
        f"| Gold fixes accepted | {summary['gold_accepted']} / {summary['gold']} |",
        f"| Safe variants accepted | {summary['benign_accepted']} / {summary['benign']} |",
        f"| Known-bad variants rejected | {summary['mutants_rejected']} / {summary['mutants']} |",
        f"| False passes | {summary['false_passes']} |",
        f"| False rejections | {summary['false_rejections']} |",
        f"| Correct verdicts | {summary['correct_verdicts']} / {summary['candidates']} "
        f"({_pct(summary['verdict_accuracy'])}) |",
        "",
        "## Two-sided matrix",
        "",
        "| | Behavior passes | Behavior fails |",
        "| :--- | ---: | ---: |",
        f"| **Security passes** | {summary['matrix']['security_pass_behavior_pass']} | "
        f"{summary['matrix']['security_pass_behavior_fail']} |",
        f"| **Security fails** | {summary['matrix']['security_fail_behavior_pass']} | "
        f"{summary['matrix']['security_fail_behavior_fail']} |",
        "",
        "## Checker comparison",
        "",
        "| Checker | Version | Recall | Precision | False repair |",
        "| :--- | :--- | ---: | ---: | ---: |",
    ]
    for checker in summary["checkers"]:
        lines.append(
            f"| {checker['name']} | {checker['version']} | "
            f"{checker['recall_hits']}/{checker['recall_total']} ({_pct(checker['recall'])}) | "
            f"{checker['precision_hits']}/{checker['precision_total']} "
            f"({_pct(checker['precision'])}) | "
            f"{checker['missed_mutants']}/{checker['mutants']} "
            f"({_pct(checker['false_repair'])}) |"
        )

    lines.extend(["", "## Tasks", ""])
    for task in results:
        status = "baseline ok" if task.baseline_ok else "baseline failed"
        lines.append(f"### `{task.task_id}`: {task.title} ({task.cwe}, {status})")
        lines.append("")
        lines.append(task.summary)
        lines.append("")
        lines.append("| Candidate | Kind | PoC | Behavior | Checker | Verdict | Correct |")
        lines.append("| :--- | :--- | ---: | ---: | ---: | :--- | :--- |")
        for candidate in task.candidates:
            verdict = "accepted" if candidate.accepted else f"rejected ({candidate.rejected_by})"
            lines.append(
                f"| {candidate.name} | {candidate.kind} | {candidate.poc_exit} | "
                f"{candidate.behavior_exit} | {candidate.checker_pass} | {verdict} | "
                f"{'yes' if candidate.correct else 'no'} |"
            )
        lines.append("")

    if summary["false_pass_ids"] or summary["false_rejection_ids"]:
        lines.extend(["## Residual risk", ""])
        if summary["false_pass_ids"]:
            lines.append("False passes:")
            lines.extend(f"- `{item}`" for item in summary["false_pass_ids"])
        if summary["false_rejection_ids"]:
            lines.append("False rejections:")
            lines.extend(f"- `{item}`" for item in summary["false_rejection_ids"])
        lines.append("")

    lines.extend(
        [
            "## Reproduce",
            "",
            "```bash",
            "uv sync --all-extras",
            "uv run acv audit",
            "```",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
