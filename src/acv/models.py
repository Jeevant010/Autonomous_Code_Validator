"""Typed records shared by the verifier, checkers, and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

CandidateKind = Literal["gold", "benign", "mutant"]
Severity = Literal["low", "medium", "high"]
ProjectCriticality = Literal["standard", "critical"]
ProjectInputMode = Literal["overlay", "diff", "candidate", "baseline"]


class CandidateManifest(BaseModel):
    """One candidate implementation that can be handed to the verifier."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1)
    path: str = Field(min_length=1)
    kind: CandidateKind
    expected_security: bool
    expected_behavior: bool = True
    note: str = ""


class ProjectCandidateManifest(BaseModel):
    """One whole-project candidate, expressed as an overlay on the base tree."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(min_length=1)
    path: str = Field(min_length=1)
    kind: CandidateKind
    expected_security: bool
    expected_behavior: bool = True
    note: str = ""


class ProjectManifest(BaseModel):
    """The on-disk contract for a multi-file project task.

    ``vulnerable`` is a complete base tree. ``poc`` and ``functional`` live
    outside that tree, so a generated overlay cannot replace the evidence that
    judges it. Each candidate is a directory of changed or added files that is
    copied over the base tree.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(pattern=r"^[a-z][a-z0-9_]{2,48}$")
    title: str = Field(min_length=3)
    cwe: str = Field(pattern=r"^CWE-[0-9]{1,4}$")
    summary: str = Field(min_length=10)
    vulnerable: str = "vulnerable"
    poc: str = "poc/exploit.py"
    functional: str = "tests/test_functional.py"
    data_dir: str = "data"
    checker_include: tuple[str, ...] = ("**/*.py",)
    checker_exclude: tuple[str, ...] = (
        "tests/**",
        "poc/**",
        "**/__pycache__/**",
        "**/.pytest_cache/**",
    )
    max_files: int = Field(default=400, ge=1, le=2000)
    max_total_bytes: int = Field(default=2_000_000, ge=1000, le=20_000_000)
    memory_mb: int = Field(default=512, ge=128, le=4096)
    poc_timeout: int = Field(default=45, ge=1, le=300)
    test_timeout: int = Field(default=180, ge=1, le=600)
    tags: tuple[str, ...] = ()
    candidates: tuple[ProjectCandidateManifest, ...]

    @field_validator("candidates")
    @classmethod
    def _has_gold_and_benign(
        cls, value: tuple[ProjectCandidateManifest, ...]
    ) -> tuple[ProjectCandidateManifest, ...]:
        kinds = {candidate.kind for candidate in value}
        if "gold" not in kinds:
            raise ValueError("a project needs at least one gold candidate")
        if "benign" not in kinds:
            raise ValueError("a project needs at least one benign candidate")
        return value


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
    path: str | None = None


@dataclass
class CheckerResult:
    tool: str
    available: bool
    findings: list[CheckFinding] = field(default_factory=list)
    version: str | None = None
    error: str | None = None
    files_scanned: int = 0
    truncated: bool = False
    coverage_complete: bool = True
    errors: dict[str, str] = field(default_factory=dict)

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


@dataclass(frozen=True)
class ProjectSpec:
    """A validated multi-file project task."""

    project_id: str
    title: str
    cwe: str
    summary: str
    root: Path
    vulnerable: Path
    poc: Path
    functional: Path
    data_dir: Path
    checker_include: tuple[str, ...]
    checker_exclude: tuple[str, ...]
    max_files: int
    max_total_bytes: int
    memory_mb: int
    poc_timeout: int
    test_timeout: int
    tags: tuple[str, ...]
    candidates: tuple[ProjectCandidateManifest, ...]


@dataclass(frozen=True)
class ProjectFileInfo:
    """One file in a materialized project tree."""

    path: str
    bytes: int
    lines: int
    sha256: str
    role: str = "source"


class ProjectProvenance(BaseModel):
    """Who produced the code under test, and how.

    This is an optional, non-authoritative record. The verifier never calls a
    model and never treats these fields as evidence. They exist so a run from a
    studio, notebook, or local model runner can be traced back to its source.
    """

    model_config = ConfigDict(extra="forbid")

    model: str = Field(default="", max_length=300)
    provider: str = Field(default="", max_length=200)
    backend: str = Field(default="", max_length=200)
    quantization: str = Field(default="", max_length=100)
    prompt: str = Field(default="", max_length=40_000)
    temperature: float | None = Field(default=None, ge=0.0, le=10.0)
    seed: int | None = None
    raw_output: str = Field(default="", max_length=400_000)
    generator_version: str = Field(default="", max_length=200)
    criticality: ProjectCriticality = "standard"
    notes: str = Field(default="", max_length=4_000)


@dataclass
class ProjectResult:
    """Gate result for a multi-file project overlay or patch."""

    project_id: str
    project_title: str
    cwe: str
    summary: str
    run_id: str
    input_mode: ProjectInputMode
    overlay_files: list[str]
    files: list[ProjectFileInfo]
    total_files: int
    total_bytes: int
    total_lines: int
    poc_exit: int
    behavior_exit: int
    poc_output: str
    behavior_output: str
    poc_output_truncated: bool
    behavior_output_truncated: bool
    security_pass: bool
    behavior_pass: bool
    checker_pass: bool
    accepted: bool
    oracle_exit: int
    oracle_output: str
    oracle_output_truncated: bool
    oracle_ok: bool
    diff_applied: bool
    reasons: list[str]
    findings: list[CheckFinding]
    checker_tool: str
    checker_results: dict[str, CheckerResult] = field(default_factory=dict)
    provenance: ProjectProvenance = field(default_factory=ProjectProvenance)
    isolation: str = "process-limits-only"
    isolation_warning: str = ""
    isolation_acknowledged: bool = False
    findings_truncated: bool = False
    elapsed_ms: int = 0
    poc_verdict: str = "unknown"

    @property
    def rejected_by(self) -> str:
        if self.accepted:
            return "none"
        if not self.oracle_ok:
            return "oracle"
        if not self.security_pass:
            return "poc"
        if not self.behavior_pass:
            return "behavior"
        if not self.checker_pass:
            return "checker"
        return "unknown"


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
    poc_verdict: str = "unknown"

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
class SourceResult:
    """A gate result for source supplied at runtime, without a ground-truth label."""

    task_id: str
    task_title: str
    cwe: str
    poc_exit: int
    behavior_exit: int
    poc_output: str
    behavior_output: str
    security_pass: bool
    behavior_pass: bool
    checker_pass: bool
    accepted: bool
    reasons: list[str]
    findings: list[CheckFinding]
    checker_tool: str
    checker_results: dict[str, CheckerResult] = field(default_factory=dict)
    elapsed_ms: int = 0
    oracle_exit: int = 1
    oracle_output: str = ""
    oracle_ok: bool = True
    diff_applied: bool = False
    input_mode: str = "source"
    candidate_code: str = ""
    applied_diff: str = ""
    poc_verdict: str = "unknown"

    @property
    def rejected_by(self) -> str:
        if self.accepted:
            return "none"
        if not self.oracle_ok:
            return "oracle"
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
