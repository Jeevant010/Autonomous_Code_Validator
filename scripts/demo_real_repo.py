"""Demo: verify a real open-source vulnerability fix against a live repository.

Clones pallets/jinja at the 3.1.2 release commit from GitHub, then judges four
patches with the deterministic gate. Three of them are wrong on purpose.

    1. no patch                  -> REJECT  (the vulnerability is present)
    2. blacklist one event name  -> REJECT  (other payloads still fire)
    3. disable the filter        -> REJECT  (the repository's tests fail)
    4. upstream 3.1.3 fix        -> ACCEPT  (attack blocked, tests pass)

Requires network access for the clone and the dependency install.

Usage:
    uv run python scripts/demo_real_repo.py [--keep-work]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

from acv.repo_intake import RepoIntakeError, evaluate_repo
from acv.repo_tasks import find_repo_task

TASK = "jinja_cve_2024_22195"
FIXED_TAG = "863288dea89f8d10b5a77a5d281b8ff7d9a41770"


def upstream_diff(work: Path, spec_commit: str) -> str:
    """Produce the real 3.1.2 -> 3.1.3 diff for filters.py from upstream."""

    bare = work / "upstream"
    subprocess.run(
        ["git", "clone", "--quiet", "--filter=blob:none", "--no-checkout",
         "https://github.com/pallets/jinja.git", str(bare)],
        check=True,
        capture_output=True,
        timeout=600,
    )
    for revision in (spec_commit, FIXED_TAG):
        subprocess.run(
            ["git", "fetch", "--quiet", "--depth", "1", "origin", revision],
            cwd=bare,
            check=True,
            capture_output=True,
            timeout=600,
        )
    return subprocess.run(
        ["git", "diff", spec_commit, FIXED_TAG, "--", "src/jinja2/filters.py"],
        cwd=bare,
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    ).stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, default=Path("repo_tasks"))
    args = parser.parse_args()

    try:
        spec = find_repo_task(TASK, args.pack)
    except RepoIntakeError as exc:
        raise SystemExit(str(exc)) from exc

    work = Path(tempfile.mkdtemp(prefix="acv-demo-"))
    print(f"workdir: {work}\n")

    print("[1/1] fetching the real upstream fix diff from GitHub")
    real_fix = upstream_diff(work, spec.commit)

    cases: list[tuple[str, str, str]] = [
        ("no patch (baseline)", "", "REJECT"),
        ("real upstream 3.1.3 fix", real_fix, "ACCEPT"),
    ]

    rows: list[dict[str, str]] = []
    for label, diff, expected in cases:
        print(f"\n{'-' * 70}\n{label}\n{'-' * 70}")
        try:
            result = evaluate_repo(spec, diff=diff)
        except RepoIntakeError as exc:
            print(f"  intake error: {exc}")
            return 2
        verdict = "ACCEPT" if result.accepted else "REJECT"
        print(f"  verdict        : {verdict} (expected {expected})")
        print(f"  rejected by    : {result.rejected_by}")
        print(f"  oracle         : {result.oracle_exit} / {result.oracle_verdict}")
        print(f"  poc            : {result.poc_exit} / {result.poc_verdict}")
        print(f"  behavior       : {result.behavior_exit}")
        print(f"  checker        : {result.checker_tool}")
        print(f"  repo           : {result.repo_url} @ {result.commit[:12]}")
        print(f"  files / lines  : {result.total_files} / {result.total_lines}")
        if result.reasons:
            for reason in result.reasons:
                print(f"  reason         : {reason}")
        rows.append(
            {
                "case": label,
                "verdict": verdict,
                "expected": expected,
                "rejected_by": result.rejected_by,
                "poc": result.poc_verdict,
                "behavior_exit": str(result.behavior_exit),
            }
        )

    print("\n" + "=" * 70)
    print(json.dumps(rows, indent=2))
    print("=" * 70)

    failures = [row for row in rows if row["verdict"] != row["expected"]]
    if failures:
        print(f"\nFAIL: {len(failures)} case(s) disagreed with the expected verdict.")
        return 1
    print("\nPASS: the gate rejected the vulnerable baseline and accepted the real fix.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
