"""Tool qualification harness.

The harness turns the calibration pack into a labeled corpus of vulnerable and
safe files, then scores every registered checker on the same corpus. This is the
first step before trusting any checker: measure it, do not assume it.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from .checkers.registry import CheckerAdapter, select_adapters
from .manifest import discover_tasks
from .models import CheckerResult, TaskSpec

SampleLabel = Literal["vulnerable", "fixed", "benign", "mutant"]


@dataclass(frozen=True)
class LabeledSample:
    """One file with a known security label."""

    sample_id: str
    task_id: str
    cwe: str
    label: SampleLabel
    path: Path
    expected_vulnerable: bool


@dataclass(frozen=True)
class CweScore:
    """Recall for one CWE family."""

    cwe: str
    positives: int
    true_positives: int
    recall: float


@dataclass
class ToolScore:
    """Qualification result for one checker."""

    tool: str
    category: str
    available: bool
    version: str | None
    error: str | None
    samples: int
    tp: int
    fp: int
    fn: int
    tn: int
    precision: float
    recall: float
    f1: float
    accuracy: float
    runtime_ms: int
    findings: int
    cwe: list[CweScore]
    false_positives: list[str]
    false_negatives: list[str]


def build_samples(pack: Path) -> list[LabeledSample]:
    """Build the labeled corpus from the task pack."""

    return build_samples_from_tasks(discover_tasks(pack))


def build_samples_from_tasks(tasks: list[TaskSpec]) -> list[LabeledSample]:
    """Build the labeled corpus from an already loaded task list."""

    samples: list[LabeledSample] = []
    for task in tasks:
        samples.append(
            LabeledSample(
                sample_id=f"{task.task_id}/vulnerable",
                task_id=task.task_id,
                cwe=task.cwe,
                label="vulnerable",
                path=task.vulnerable,
                expected_vulnerable=True,
            )
        )
        samples.append(
            LabeledSample(
                sample_id=f"{task.task_id}/fixed",
                task_id=task.task_id,
                cwe=task.cwe,
                label="fixed",
                path=task.fixed,
                expected_vulnerable=False,
            )
        )

        for candidate in task.candidates:
            if candidate.kind == "gold":
                continue
            samples.append(
                LabeledSample(
                    sample_id=f"{task.task_id}/{candidate.name}",
                    task_id=task.task_id,
                    cwe=task.cwe,
                    label="mutant" if candidate.kind == "mutant" else "benign",
                    path=task.root / candidate.path,
                    expected_vulnerable=not candidate.expected_security,
                )
            )

    return samples


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def score_adapter(adapter: CheckerAdapter, samples: list[LabeledSample]) -> ToolScore:
    """Run one checker over the corpus and compute its detection metrics."""

    start = time.perf_counter()

    if not adapter.available:
        return ToolScore(
            tool=adapter.name,
            category=adapter.category,
            available=False,
            version=adapter.version,
            error="checker is not installed",
            samples=len(samples),
            tp=0,
            fp=0,
            fn=0,
            tn=0,
            precision=0.0,
            recall=0.0,
            f1=0.0,
            accuracy=0.0,
            runtime_ms=0,
            findings=0,
            cwe=[],
            false_positives=[],
            false_negatives=[],
        )

    tp = 0
    fp = 0
    fn = 0
    tn = 0
    findings = 0
    false_positives: list[str] = []
    false_negatives: list[str] = []
    cwe_counts: dict[str, list[int]] = {}

    for sample in samples:
        try:
            result: CheckerResult = adapter.run(sample.path)
        except Exception as exc:
            return ToolScore(
                tool=adapter.name,
                category=adapter.category,
                available=False,
                version=adapter.version,
                error=f"{sample.sample_id}: {type(exc).__name__}: {exc}",
                samples=len(samples),
                tp=0,
                fp=0,
                fn=0,
                tn=0,
                precision=0.0,
                recall=0.0,
                f1=0.0,
                accuracy=0.0,
                runtime_ms=int((time.perf_counter() - start) * 1000),
                findings=0,
                cwe=[],
                false_positives=[],
                false_negatives=[],
            )

        if not result.available:
            return ToolScore(
                tool=adapter.name,
                category=adapter.category,
                available=False,
                version=result.version or adapter.version,
                error=result.error or "checker returned unavailable",
                samples=len(samples),
                tp=0,
                fp=0,
                fn=0,
                tn=0,
                precision=0.0,
                recall=0.0,
                f1=0.0,
                accuracy=0.0,
                runtime_ms=int((time.perf_counter() - start) * 1000),
                findings=0,
                cwe=[],
                false_positives=[],
                false_negatives=[],
            )

        findings += len(result.findings)
        predicted_vulnerable = bool(result.blocking)

        if sample.expected_vulnerable:
            counts = cwe_counts.setdefault(sample.cwe, [0, 0])
            counts[0] += 1
            if predicted_vulnerable:
                tp += 1
                counts[1] += 1
            else:
                fn += 1
                false_negatives.append(sample.sample_id)
        elif predicted_vulnerable:
            fp += 1
            false_positives.append(sample.sample_id)
        else:
            tn += 1

    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = _ratio(2 * precision * recall, precision + recall)
    accuracy = _ratio(tp + tn, tp + tn + fp + fn)

    cwe = [
        CweScore(
            cwe=name,
            positives=counts[0],
            true_positives=counts[1],
            recall=_ratio(counts[1], counts[0]),
        )
        for name, counts in sorted(cwe_counts.items())
    ]

    return ToolScore(
        tool=adapter.name,
        category=adapter.category,
        available=True,
        version=adapter.version,
        error=None,
        samples=len(samples),
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        precision=precision,
        recall=recall,
        f1=f1,
        accuracy=accuracy,
        runtime_ms=int((time.perf_counter() - start) * 1000),
        findings=findings,
        cwe=cwe,
        false_positives=false_positives,
        false_negatives=false_negatives,
    )


def evaluate_checkers(
    pack: Path,
    names: set[str] | None = None,
    tasks: list[TaskSpec] | None = None,
) -> list[ToolScore]:
    """Qualify the requested checkers, or every registered checker."""

    samples = build_samples_from_tasks(tasks) if tasks is not None else build_samples(pack)
    return [score_adapter(adapter, samples) for adapter in select_adapters(names)]


def write_qualification_json(path: Path, scores: list[ToolScore]) -> Path:
    """Write the full qualification payload."""

    payload = {
        "generated": datetime.now(UTC).isoformat(timespec="seconds"),
        "tools": [asdict(score) for score in scores],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def write_qualification_markdown(path: Path, scores: list[ToolScore]) -> Path:
    """Write a compact human-readable leaderboard."""

    lines = [
        "# Checker Qualification",
        "",
        f"Generated: `{datetime.now(UTC).isoformat(timespec='seconds')}`",
        "",
        "| Tool | Available | TP | FP | FN | TN | Precision | Recall | F1 | Runtime |",
        "| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for score in scores:
        if not score.available:
            lines.append(
                f"| `{score.tool}` | no | - | - | - | - | - | - | - | - |"
            )
            continue
        lines.append(
            f"| `{score.tool}` | yes | {score.tp} | {score.fp} | {score.fn} | {score.tn} | "
            f"{score.precision * 100:.1f}% | {score.recall * 100:.1f}% | "
            f"{score.f1 * 100:.1f}% | {score.runtime_ms} ms |"
        )

    lines.extend(["", "## False negatives", ""])
    any_fn = False
    for score in scores:
        for sample in score.false_negatives:
            any_fn = True
            lines.append(f"- `{score.tool}`: `{sample}`")
    if not any_fn:
        lines.append("- none")

    lines.extend(["", "## False positives", ""])
    any_fp = False
    for score in scores:
        for sample in score.false_positives:
            any_fp = True
            lines.append(f"- `{score.tool}`: `{sample}`")
    if not any_fp:
        lines.append("- none")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
