"""Run the whole real-repository suite and produce a results table and dashboard.

For every task this runs three cases against a live clone of the pinned commit:

    baseline   no patch at all           expected REJECT
    fix        the real upstream fix      expected ACCEPT
    half-fix   a patch that looks right  expected REJECT

The half-fix is derived per task, so the negative control is not a shared stub.

Outputs:
    reports/repo_benchmark.json   machine-readable record
    reports/repo_dashboard.html   self-contained dashboard

Usage:
    uv run python scripts/benchmark_repos.py [--only TASK] [--no-html]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import time
from pathlib import Path

from acv.repo_intake import RepoIntakeError, RepoSpec, evaluate_repo
from acv.repo_report import render_dashboard
from acv.repo_tasks import discover_repo_tasks
from acv.stale import probe_default_branch

# Each entry is (source path, exact text, replacement text). The half fix is a
# plausible but incomplete repair; the benchmark builds a real git diff from it
# so the patch cannot be malformed.
_JINJA_OLD = (
    '    rv = " ".join(\n'
    '        f\'{escape(key)}="{escape(value)}"\'\n'
    "        for key, value in d.items()\n"
    "        if value is not None and not isinstance(value, Undefined)\n"
    "    )"
)
_JINJA_NEW = (
    "    def _clean(k: str) -> str:\n"
    '        return k.replace("onmouseover", "")\n'
    "\n"
    '    rv = " ".join(\n'
    '        f\'{escape(_clean(key))}="{escape(value)}"\'\n'
    "        for key, value in d.items()\n"
    "        if value is not None and not isinstance(value, Undefined)\n"
    "    )"
)

# A realistic incomplete fix: remove the well-known python/object vector but
# leave python/module registered, which still hands back any module object.
_YAML_OLD = (
    "FullConstructor.add_multi_constructor(\n"
    "    'tag:yaml.org,2002:python/object:',\n"
    "    FullConstructor.construct_python_object)\n"
    "\n"
    "FullConstructor.add_multi_constructor(\n"
    "    'tag:yaml.org,2002:python/object/new:',\n"
    "    FullConstructor.construct_python_object_new)"
)
_YAML_NEW = "# python/object constructors removed"

_URLLIB3_OLD = '            if response.status == 303:\n                method = "GET"\n'
_URLLIB3_NEW = (
    '            if response.status == 303:\n'
    '                method = "GET"\n'
    "                body = None\n"
)

_GITPYTHON_OLD = (
    "        proc = git.clone(\n"
    "            multi,\n"
    "            Git.polish_url(str(url)),\n"
)
_GITPYTHON_NEW = (
    "        proc = git.clone(\n"
    "            multi,\n"
    '            "--",\n'
    "            Git.polish_url(str(url)),\n"
)

_SQLPARSE_OLD = (
    "        for token in self.tokens:\n"
    "            if token.is_group:\n"
    "                yield from token.flatten()\n"
    "            else:\n"
    "                yield token\n"
)
_SQLPARSE_NEW = (
    "        try:\n"
    "            for token in self.tokens:\n"
    "                if token.is_group:\n"
    "                    yield from token.flatten()\n"
    "                else:\n"
    "                    yield token\n"
    "        except ValueError:\n"
    "            return\n"
)

_CLICK_OLD = "        self.name = name\n"
_CLICK_NEW = (
    "        import subprocess; subprocess.Popen(str(name), shell=True)\n"
    "        self.name = name\n"
)

HALF_FIXES: dict[str, tuple[str, str, str]] = {
    "gitpython_cve_2022_24439": (
        "git/repo/base.py",
        _GITPYTHON_OLD,
        _GITPYTHON_NEW,
    ),
    "sqlparse_cve_2024_4340": (
        "sqlparse/sql.py",
        _SQLPARSE_OLD,
        _SQLPARSE_NEW,
    ),
    "click_clean_baseline": (
        "src/click/core.py",
        _CLICK_OLD,
        _CLICK_NEW,
    ),
    "jinja_cve_2024_22195": (
        "src/jinja2/filters.py",
        _JINJA_OLD,
        _JINJA_NEW,
    ),
    "pyyaml_cve_2020_14343": (
        "lib3/yaml/constructor.py",
        _YAML_OLD,
        _YAML_NEW,
    ),
    "requests_cve_2023_32681": (
        "requests/sessions.py",
        "        if username and password:\n",
        '        if "Authorization" not in headers and username and password:\n',
    ),
    "urllib3_cve_2023_43848": (
        "src/urllib3/connectionpool.py",
        _URLLIB3_OLD,
        _URLLIB3_NEW,
    ),
}

WEB_DIR = Path("src/acv/web")


def upstream_diff(spec: RepoSpec, work: Path) -> str:
    """Diff the pinned commit against the recorded fix commit, from upstream."""

    if spec.clean_baseline:
        return ""
    fix_commit = spec.fix_commit
    if not fix_commit:
        raise RepoIntakeError(f"{spec.task_id} has no fix_commit in task.json")

    bare = work / f"upstream-{spec.task_id}"
    subprocess.run(
        ["git", "clone", "--quiet", "--filter=blob:none", "--no-checkout",
         spec.repo_url, str(bare)],
        check=True,
        capture_output=True,
        timeout=900,
    )
    for revision in (spec.commit, fix_commit):
        subprocess.run(
            ["git", "fetch", "--quiet", "--depth", "1", "origin", revision],
            cwd=bare,
            check=True,
            capture_output=True,
            timeout=900,
        )
    # Diff only the source paths. A release commit also bumps version files and
    # adds tests, and the gate must never be handed a diff that edits its own
    # tests. Restricting the diff keeps the comparison to the actual fix.
    command = ["git", "diff", spec.commit, fix_commit]
    if spec.diff_paths:
        command += ["--", *spec.diff_paths]
    return subprocess.run(
        command,
        cwd=bare,
        capture_output=True,
        text=True,
        check=True,
        timeout=300,
    ).stdout


def half_fix_diff(spec: RepoSpec, work: Path) -> str:
    """Build a valid unified diff for the half fix using git itself.

    Writing hunk headers by hand is error-prone; letting git produce the diff
    means the patch is always well formed and always applies to the pinned tree.
    """

    entry = HALF_FIXES.get(spec.task_id)
    if entry is None:
        return ""
    path, old, new = entry

    tree = work / f"halffix-{spec.task_id}"
    if not tree.exists():
        subprocess.run(
            ["git", "clone", "--quiet", "--depth", "1", spec.repo_url, str(tree)],
            check=True,
            capture_output=True,
            timeout=900,
        )
        subprocess.run(
            ["git", "fetch", "--quiet", "--depth", "1", "origin", spec.commit],
            cwd=tree,
            check=True,
            capture_output=True,
            timeout=900,
        )
        subprocess.run(
            ["git", "checkout", "--quiet", "--detach", spec.commit],
            cwd=tree,
            check=True,
            capture_output=True,
            timeout=300,
        )

    target = tree / path
    source = target.read_text(encoding="utf-8")
    if old not in source:
        raise RepoIntakeError(f"half fix anchor not found in {path}")

    target.write_text(source.replace(old, new, 1), encoding="utf-8")
    diff = subprocess.run(
        ["git", "diff", "--", path],
        cwd=tree,
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    ).stdout
    subprocess.run(
        ["git", "checkout", "--", path], cwd=tree, check=True, capture_output=True, timeout=120
    )
    return diff


def run_case(spec: RepoSpec, diff: str) -> dict[str, object]:
    try:
        result = evaluate_repo(spec, diff=diff)
    except RepoIntakeError as exc:
        return {"verdict": "ERROR", "rejected_by": "intake", "error": str(exc)}
    return {
        "verdict": "ACCEPT" if result.accepted else "REJECT",
        "rejected_by": result.rejected_by,
        "oracle": result.oracle_verdict,
        "poc": result.poc_verdict,
        "behavior_exit": result.behavior_exit,
        "checker": result.checker_tool,
        "checker_ok": result.checker_pass,
        "files": result.total_files,
        "lines": result.total_lines,
        "changed": result.changed_files,
        "elapsed_ms": result.elapsed_ms,
        "reasons": result.reasons,
        "repo_url": result.repo_url,
        "commit": result.commit,
        "isolation": result.isolation,
        "findings": len(result.findings),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pack", type=Path, default=Path("repo_tasks"))
    parser.add_argument("--only", default="", help="run a single task id")
    parser.add_argument("--no-html", action="store_true")
    args = parser.parse_args()

    tasks = discover_repo_tasks(args.pack)
    if args.only:
        tasks = [task for task in tasks if task.task_id == args.only]
    if not tasks:
        raise SystemExit("no repo tasks found")

    work = Path(tempfile.mkdtemp(prefix="acv-bench-"))
    rows: list[dict[str, object]] = []

    for spec in tasks:
        print(f"\n{'=' * 76}\n{spec.task_id}  ({spec.cwe})\n{spec.repo_url}\n{'=' * 76}")
        try:
            real_fix = upstream_diff(spec, work)
            half_fix = half_fix_diff(spec, work)
        except (RepoIntakeError, subprocess.CalledProcessError) as exc:
            print(f"  cannot build the patches: {exc}")
            rows.append({"task": spec.task_id, "cwe": spec.cwe, "error": str(exc)})
            continue

        if spec.clean_baseline:
            cases = [
                ("baseline", "", "ACCEPT"),
                ("mutant (backdoor)", half_fix, "REJECT"),
            ]
        else:
            cases = [
                ("baseline", "", "REJECT"),
                ("upstream fix", real_fix, "ACCEPT"),
                ("half fix", half_fix, "REJECT"),
            ]

        record: dict[str, object] = {
            "task": spec.task_id,
            "title": spec.title,
            "cwe": spec.cwe,
            "repo_url": spec.repo_url,
            "commit": spec.commit,
            "cases": {},
        }
        for label, diff, expected in cases:
            if label == "half fix" and not diff:
                continue
            started = time.perf_counter()
            outcome = run_case(spec, diff)
            outcome["expected"] = expected
            outcome["ok"] = outcome.get("verdict") == expected
            outcome["wall_ms"] = int((time.perf_counter() - started) * 1000)
            record["cases"][label] = outcome  # type: ignore[index]
            marker = "ok  " if outcome["ok"] else "FAIL"
            print(
                f"  {marker} {label:14} -> {outcome.get('verdict'):7} "
                f"(expected {expected}, rejected by {outcome.get('rejected_by')})"
            )
        try:
            live = probe_default_branch(spec)
            record["live"] = {
                "status": live.status,
                "branch": live.branch,
                "head_commit": live.head_commit,
                "detail": live.detail,
            }
            print(f"  live status    -> {live.status} on {live.branch}")
        except RepoIntakeError as exc:
            record["live"] = {"status": "unknown", "detail": str(exc)[:200]}
            print(f"  live status    -> could not check: {exc}")

        rows.append(record)

    reports = Path("reports")
    reports.mkdir(exist_ok=True)
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tasks": rows,
        "totals": _totals(rows),
    }
    (reports / "repo_benchmark.json").write_text(json.dumps(payload, indent=2) + "\n")

    print("\n" + "=" * 76)
    print(json.dumps(payload["totals"], indent=2))
    print("=" * 76)

    if not args.no_html:
        html = render_dashboard(payload)
        (reports / "repo_dashboard.html").write_text(html, encoding="utf-8")
        print(f"\nwrote {reports / 'repo_benchmark.json'}")
        print(f"wrote {reports / 'repo_dashboard.html'}")

    failures = payload["totals"]["disagreements"]
    return 1 if failures else 0


def _totals(rows: list[dict[str, object]]) -> dict[str, object]:
    cases = [case for row in rows if "cases" in row for case in row["cases"].values()]  # type: ignore[union-attr]
    return {
        "tasks": len([row for row in rows if "cases" in row]),
        "cases": len(cases),
        "agreements": len([case for case in cases if case.get("ok")]),
        "disagreements": len([case for case in cases if not case.get("ok")]),
        "false_accepts": len(
            [case for case in cases if case.get("verdict") == "ACCEPT" and case.get("expected") == "REJECT"]
        ),
        "false_rejects": len(
            [case for case in cases if case.get("verdict") == "REJECT" and case.get("expected") == "ACCEPT"]
        ),
        "accepted": len([case for case in cases if case.get("verdict") == "ACCEPT"]),
        "rejected": len([case for case in cases if case.get("verdict") == "REJECT"]),
    }


if __name__ == "__main__":
    raise SystemExit(main())
