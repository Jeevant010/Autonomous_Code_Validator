"""Typed records shared by the verifier, checkers, and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

CandidateKind = Literal["gold", "benign", "mutant"]
Severity = Literal["low", "medium", "high"]


class CandidateManifest(BaseModel):
    """One candidate implementation that can be handed to the verifier."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1)
    path: str = Field(min_length=1)
    kind: CandidateKind
    expected_security: bool
    expected_behavior: bool = True
    note: str = ""


class TaskManifest(BaseModel):
    """The on-disk contract for a security worker task."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(pattern=r"^[a-z][a-z0-9_]{2,48}$")
    title: str = Field(min_length=3)
    cwe: str = Field(pattern=r"^CWE-[0-9]{1,4}$")
    summary: str = Field(min_length=10)
    vulnerable: str = "vulnerable/worker.py"
    fixed: str = "fixed/worker.py"
    poc: str = "poc/exploit.py"
    functional: str = "tests/test_functional.py"
    data_dir: str = "data"
    tags: tuple[str, ...] = ()
    candidates: tuple[CandidateManifest, ...]

    @field_validator("candidates")
    @classmethod
    def _has_gold_and_benign(
        cls, value: tuple[CandidateManifest, ...]
    ) -> tuple[CandidateManifest, ...]:
        kinds = {candidate.kind for candidate in value}
        if "gold" not in kinds:
            raise ValueError("a task needs at least one gold candidate")
        if "benign" not in kinds:
            raise ValueError("a task needs at least one benign candidate")
        return value


@dataclass(frozen=True)
class CheckFinding:
    rule_id: str
    cwe: str
    severity: Severity
    message: str
    line: int | None = None


@dataclass
class CheckerResult:
    tool: str
    available: bool
    findings: list[CheckFinding] = field(default_factory=list)
    version: str | None = None
    error: str | None = None

    @property
    def blocking(self) -> list[CheckFinding]:
        return [finding for finding in self.findings if finding.severity in {"medium", "high"}]

    @property
    def passed(self) -> bool:
        return self.available and not self.blocking


@dataclass(frozen=True)
class TaskSpec:
    task_id: str
    title: str
    cwe: str
    summary: str
    root: Path
    vulnerable: Path
    fixed: Path
    poc: Path
    functional: Path
    data_dir: Path
    tags: tuple[str, ...]
    candidates: tuple[CandidateManifest, ...]


@dataclass
class CandidateResult:
    task_id: str
    task_title: str
    cwe: str
    name: str
    kind: CandidateKind
    expected_security: bool
    expected_behavior: bool
    poc_exit: int
    behavior_exit: int
    poc_output: str
    behavior_output: str
    security_pass: bool
    behavior_pass: bool
    checker_pass: bool
    accepted: bool
    expected_accepted: bool
    correct: bool
    reasons: list[str]
    findings: list[CheckFinding]
    checker_tool: str
    checker_results: dict[str, CheckerResult] = field(default_factory=dict)

    @property
    def rejected_by(self) -> str:
        if self.accepted:
            return "none"
        if not self.security_pass:
            return "poc"
        if not self.behavior_pass:
            return "behavior"
        if not self.checker_pass:
            return "checker"
        return "unknown"


@dataclass
class TaskResult:
    task_id: str
    title: str
    cwe: str
    summary: str
    tags: tuple[str, ...]
    vulnerable_poc_exit: int
    fixed_poc_exit: int
    fixed_behavior_exit: int
    baseline_ok: bool
    candidates: list[CandidateResult]
    checker_summary: dict[str, dict[str, float | int | str | bool]]
