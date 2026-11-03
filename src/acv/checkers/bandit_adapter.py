"""Bandit adapter.

Bandit is used as a second, independent opinion. It is not required for the
gate to function, but it makes the checker comparison concrete.
"""

from __future__ import annotations

import json
import subprocess
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from ..models import CheckerResult, CheckFinding, Severity


def _version() -> str | None:
    try:
        return version("bandit")
    except PackageNotFoundError:
        return None


def _severity(value: object) -> Severity:
    text = str(value).lower()
    if text in {"high", "medium", "low"}:
        return text  # type: ignore[return-value]
    return "medium"


def run_bandit(path: Path, timeout: int = 60) -> CheckerResult:
    """Run Bandit and normalize its JSON output."""

    try:
        proc = subprocess.run(
            [sys.executable, "-m", "bandit", "-f", "json", "-q", str(path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return CheckerResult(tool="bandit", available=False, error=str(exc))

    if not proc.stdout.strip():
        return CheckerResult(
            tool="bandit",
            available=True,
            version=_version(),
            error=proc.stderr.strip()[:500] or "no JSON output",
        )

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return CheckerResult(
            tool="bandit",
            available=True,
            version=_version(),
            error=f"invalid JSON: {exc}",
        )

    findings: list[CheckFinding] = []
    for item in payload.get("results", []):
        if not isinstance(item, dict):
            continue
        cwe = item.get("issue_cwe")
        cwe_id = cwe.get("id") if isinstance(cwe, dict) else None
        findings.append(
            CheckFinding(
                rule_id=str(item.get("test_id", "BANDIT")),
                cwe=f"CWE-{cwe_id}" if cwe_id else "CWE-UNKNOWN",
                severity=_severity(item.get("issue_severity", "medium")),
                message=str(item.get("issue_text", "Bandit finding")),
                line=item.get("line_number") if isinstance(item.get("line_number"), int) else None,
            )
        )

    return CheckerResult(
        tool="bandit",
        available=True,
        findings=findings,
        version=_version(),
        error=proc.stderr.strip()[:500] if proc.returncode not in {0, 1} else None,
    )
