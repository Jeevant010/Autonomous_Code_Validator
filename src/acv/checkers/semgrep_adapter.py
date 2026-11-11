"""Optional Semgrep adapter.

Semgrep is not required to run the verifier. When it is installed, this adapter
normalizes its JSON output into the same ``CheckerResult`` shape as the built-in
rules and Bandit. The rule pack defaults to ``p/python`` and can be overridden
with ``ACV_SEMGREP_CONFIG``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from ..models import CheckerResult, CheckFinding, Severity

CWE_PATTERN = re.compile(r"CWE-\d+")


def _severity(value: object) -> Severity:
    text = str(value).upper()
    if text in {"ERROR", "HIGH"}:
        return "high"
    if text in {"WARNING", "MEDIUM"}:
        return "medium"
    return "low"


def _extract_cwe(extra: dict[str, object]) -> str:
    metadata = extra.get("metadata")
    if not isinstance(metadata, dict):
        return "CWE-UNKNOWN"

    raw = metadata.get("cwe")
    values = raw if isinstance(raw, list) else [raw]
    for value in values:
        match = CWE_PATTERN.search(str(value))
        if match:
            return match.group(0)
    return "CWE-UNKNOWN"


def run_semgrep(path: Path, timeout: int = 90) -> CheckerResult:
    """Run Semgrep and normalize its findings."""

    executable = shutil.which("semgrep")
    if executable is None:
        return CheckerResult(tool="semgrep", available=False, error="semgrep is not installed")

    config = os.environ.get("ACV_SEMGREP_CONFIG", "p/python")
    command = [
        executable,
        "scan",
        "--json",
        "--quiet",
        "--metrics=off",
        "--config",
        config,
        str(path),
    ]

    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return CheckerResult(tool="semgrep", available=False, error=str(exc))

    if not proc.stdout.strip():
        return CheckerResult(
            tool="semgrep",
            available=True,
            error=proc.stderr.strip()[:500] or "no JSON output",
        )

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return CheckerResult(
            tool="semgrep",
            available=True,
            error=f"invalid JSON: {exc}",
        )

    if not isinstance(payload, dict):
        return CheckerResult(
            tool="semgrep",
            available=True,
            error="unexpected JSON payload",
        )

    results = payload.get("results", [])
    if not isinstance(results, list):
        return CheckerResult(
            tool="semgrep",
            available=True,
            error="unexpected results payload",
        )

    findings: list[CheckFinding] = []
    for item in results:
        if not isinstance(item, dict):
            continue

        extra = item.get("extra")
        if not isinstance(extra, dict):
            extra = {}

        start = item.get("start")
        line = start.get("line") if isinstance(start, dict) else None

        findings.append(
            CheckFinding(
                rule_id=str(item.get("check_id", "SEMGREP")),
                cwe=_extract_cwe(extra),
                severity=_severity(extra.get("severity")),
                message=str(extra.get("message", "Semgrep finding")),
                line=line if isinstance(line, int) else None,
            )
        )

    error = proc.stderr.strip()[:500] if proc.returncode not in {0, 1} else None
    return CheckerResult(tool="semgrep", available=True, findings=findings, error=error)
