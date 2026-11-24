"""Command-line interface for the validator."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from . import __version__
from .checkers import checker_adapters
from .harden import HardenRefused, build_hardening_branch
from .llm import GroqError
from .manifest import discover_tasks, load_task
from .models import ProjectProvenance
from .projects import (
    ProjectError,
    discover_projects,
    evaluate_project,
    evaluate_project_candidate,
    find_project,
)
from .repo_intake import RepoIntakeError, evaluate_repo
from .repo_tasks import discover_repo_tasks, find_repo_task
from .report import aggregate, write_json, write_markdown
from .review import ReviewError, find_candidate, review_by_id
from .runner import CheckerName, evaluate_candidate, run_audit
from .stale import probe_default_branch
from .toolbench import (
    evaluate_checkers,
    write_qualification_json,
    write_qualification_markdown,
)

app = typer.Typer(
    name="acv",
    help="Two-sided verification for security changes.",
    no_args_is_help=True,
)
console = Console()


def _checker(value: str) -> CheckerName:
    if value not in {"acv-rules", "bandit", "semgrep"}:
        raise typer.BadParameter("checker must be acv-rules, bandit, or semgrep")
    return value  # type: ignore[return-value]


def _relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path)


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


@app.command()
def version() -> None:
    """Print the validator version."""
    console.print(f"Autonomous Code Validator {__version__}")


@app.command("tools")
def list_tools() -> None:
    """List checker adapters and whether they are installed."""
    table = Table(title="Checker adapters")
    table.add_column("Tool")
    table.add_column("Category")
    table.add_column("Languages", overflow="fold")
    table.add_column("Installed")
    table.add_column("Version")
    table.add_column("Description", overflow="fold")
    for adapter in checker_adapters():
        table.add_row(
            adapter.name,
            adapter.category,
            ", ".join(adapter.languages),
            "yes" if adapter.available else "no",
            adapter.version or "-",
            adapter.description,
        )
    console.print(table)
    console.print("[dim]Measure them on the labeled pack: uv run acv qualify[/dim]")


@app.command()
def qualify(
    pack: Annotated[Path, typer.Option("--pack", help="Security pack directory.")] = Path(
        "security_workers"
    ),
    checker: Annotated[
        list[str] | None,
        typer.Option("--checker", help="Only qualify these adapters. Repeat the option."),
    ] = None,
    json_path: Annotated[
        Path,
        typer.Option("--json", help="Where to write the full qualification payload."),
    ] = Path("reports/checkers.json"),
    markdown_path: Annotated[
        Path,
        typer.Option("--markdown", help="Where to write the human-readable leaderboard."),
    ] = Path("reports/checkers.md"),
) -> None:
    """Measure checker recall, false positives, and runtime on the labeled pack."""
    names = set(checker) if checker else None
    try:
        scores = evaluate_checkers(pack, names)
    except KeyError as exc:
        raise typer.BadParameter(str(exc)) from exc

    table = Table(title="Checker qualification")
    table.add_column("Tool")
    table.add_column("Available")
    table.add_column("TP", justify="right")
    table.add_column("FP", justify="right")
    table.add_column("FN", justify="right")
    table.add_column("TN", justify="right")
    table.add_column("Precision", justify="right")
    table.add_column("Recall", justify="right")
    table.add_column("F1", justify="right")
    table.add_column("Runtime", justify="right")

    for score in scores:
        if not score.available:
            table.add_row(
                score.tool,
                "no",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                score.error or "unavailable",
            )
            continue
        positives = score.tp + score.fn
        table.add_row(
            score.tool,
            "yes",
            f"{score.tp}/{positives}",
            str(score.fp),
            str(score.fn),
            str(score.tn),
            _pct(score.precision),
            _pct(score.recall),
            _pct(score.f1),
            f"{score.runtime_ms} ms",
        )
    console.print(table)

    false_negatives = [
        (score.tool, sample)
        for score in scores
        for sample in score.false_negatives
    ]
    if false_negatives:
        misses = Table(title="False negatives: vulnerable files the checker missed")
        misses.add_column("Tool")
        misses.add_column("Sample", overflow="fold")
        for tool, sample in false_negatives:
            misses.add_row(tool, sample)
        console.print(misses)

    false_positives = [
        (score.tool, sample)
        for score in scores
        for sample in score.false_positives
    ]
    if false_positives:
        noise = Table(title="False positives: safe files the checker flagged")
        noise.add_column("Tool")
        noise.add_column("Sample", overflow="fold")
        for tool, sample in false_positives:
            noise.add_row(tool, sample)
        console.print(noise)

    write_qualification_json(json_path, scores)
    write_qualification_markdown(markdown_path, scores)
    console.print(f"JSON: {json_path}")
    console.print(f"Markdown: {markdown_path}")
    console.print(
        "[dim]Dynamic gate: run `uv run acv audit` for exploit and test verification.[/dim]"
    )


@app.command("list")
def list_tasks(
    pack: Annotated[Path, typer.Option("--pack", help="Security pack directory.")] = Path(
        "security_workers"
    ),
) -> None:
    """List the tasks in a security pack."""
    tasks = discover_tasks(pack)
    table = Table(title="Security worker pack")
    table.add_column("Task")
    table.add_column("CWE")
    table.add_column("Title")
    table.add_column("Vulnerable code", overflow="fold")
    table.add_column("Candidates", justify="right")
    for task in tasks:
        table.add_row(
            task.task_id,
            task.cwe,
            task.title,
            _relative(task.vulnerable),
            str(len(task.candidates)),
        )
    console.print(table)


@app.command()
def audit(
    pack: Annotated[Path, typer.Option("--pack", help="Security pack directory.")] = Path(
        "security_workers"
    ),
    task: Annotated[
        list[str] | None,
        typer.Option("--task", help="Limit the run to one or more task ids."),
    ] = None,
    checker: Annotated[
        str,
        typer.Option("--checker", help="Primary checker: acv-rules or bandit."),
    ] = "acv-rules",
    json_path: Annotated[
        Path,
        typer.Option("--json", help="Where to write the raw result JSON."),
    ] = Path("reports/results.json"),
    markdown_path: Annotated[
        Path,
        typer.Option("--markdown", help="Where to write the Markdown report."),
    ] = Path("reports/summary.md"),
) -> None:
    """Run the two-sided audit and write the reports."""
    primary = _checker(checker)
    selected = set(task) if task else None
    results = run_audit(pack, primary_checker=primary, task_ids=selected)
    write_json(json_path, results)
    write_markdown(markdown_path, results)
    summary = aggregate(results)

    table = Table(title="Two-sided audit")
    table.add_column("Task")
    table.add_column("Baseline")
    table.add_column("Gold", justify="right")
    table.add_column("Safe", justify="right")
    table.add_column("Mutants", justify="right")
    table.add_column("False pass", justify="right")
    table.add_column("False reject", justify="right")

    for result in results:
        gold = [c for c in result.candidates if c.kind == "gold"]
        benign = [c for c in result.candidates if c.kind == "benign"]
        mutants = [c for c in result.candidates if c.kind == "mutant"]
        table.add_row(
            result.task_id,
            "ok" if result.baseline_ok else "FAIL",
            f"{sum(1 for c in gold if c.accepted)}/{len(gold)}",
            f"{sum(1 for c in benign if c.accepted)}/{len(benign)}",
            f"{sum(1 for c in mutants if not c.accepted)}/{len(mutants)}",
            str(sum(1 for c in mutants if c.accepted)),
            str(sum(1 for c in gold + benign if not c.accepted)),
        )
    console.print(table)

    console.print(
        f"\n[bold]{summary['correct_verdicts']}/{summary['candidates']}[/bold] correct verdicts "
        f"([bold]{summary['verdict_accuracy'] * 100:.1f}%[/bold]) across "
        f"{summary['tasks']} tasks and {summary['cwe_families']} CWE families."
    )
    console.print(f"JSON: {json_path}")
    console.print(f"Markdown: {markdown_path}")


@app.command("projects")
def list_projects(
    pack: Annotated[Path, typer.Option("--pack", help="Project pack directory.")] = Path(
        "project_workers"
    ),
) -> None:
    """List multi-file project tasks and their size profile."""

    try:
        projects = discover_projects(pack)
    except ProjectError as exc:
        raise typer.BadParameter(str(exc)) from exc
    table = Table(title="Multi-file project pack")
    table.add_column("Project")
    table.add_column("CWE")
    table.add_column("Title")
    table.add_column("Files", justify="right")
    table.add_column("Lines", justify="right")
    table.add_column("Candidates", justify="right")
    for project in projects:
        files = [
            path
            for path in project.vulnerable.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts
        ]
        lines = sum(
            len(path.read_text(encoding="utf-8", errors="replace").splitlines())
            for path in files
        )
        table.add_row(
            project.project_id,
            project.cwe,
            project.title,
            str(len(files)),
            str(lines),
            str(len(project.candidates)),
        )
    console.print(table)


@app.command("verify-project")
def verify_project(
    project_id: Annotated[str, typer.Argument(help="Project id, for example doc_portal.")],
    candidate: Annotated[
        str | None,
        typer.Option("--candidate", help="Named reference or mutant candidate."),
    ] = None,
    overlay: Annotated[
        Path | None,
        typer.Option(
            "--overlay",
            help="JSON file containing a path -> text object, or an object with a files key.",
        ),
    ] = None,
    model: Annotated[
        str | None,
        typer.Option("--model", help="Optional model name for the provenance record."),
    ] = None,
    pack: Annotated[Path, typer.Option("--pack", help="Project pack directory.")] = Path(
        "project_workers"
    ),
    checker: Annotated[
        str,
        typer.Option("--checker", help="Primary checker: acv-rules or bandit."),
    ] = "acv-rules",
    as_json: Annotated[bool, typer.Option("--json", help="Print the full result as JSON.")] = False,
) -> None:
    """Run the deterministic gate on a multi-file project."""

    if candidate and overlay:
        raise typer.BadParameter("use either --candidate or --overlay, not both")
    try:
        project = find_project([pack], project_id)
    except ProjectError as exc:
        raise typer.BadParameter(str(exc)) from exc

    provenance = ProjectProvenance(model=model or "", backend="cli")
    try:
        if candidate:
            result = evaluate_project_candidate(
                project,
                candidate,
                provenance=provenance,
                primary_checker=_checker(checker),
            )
        else:
            files: dict[str, str] = {}
            if overlay is not None:
                try:
                    payload = json.loads(overlay.read_text(encoding="utf-8"))
                except (OSError, ValueError) as exc:
                    raise typer.BadParameter(f"could not read overlay JSON: {exc}") from exc
                if not isinstance(payload, dict):
                    raise typer.BadParameter("overlay JSON must be an object")
                raw_files = payload.get("files", payload)
                if not isinstance(raw_files, dict):
                    raise typer.BadParameter("overlay 'files' must be an object")
                files = {str(name): str(text) for name, text in raw_files.items()}
            result = evaluate_project(
                project,
                files,
                input_mode="overlay" if files else "baseline",
                provenance=provenance,
                primary_checker=_checker(checker),
            )
    except ProjectError as exc:
        raise typer.BadParameter(str(exc)) from exc

    if as_json:
        console.print_json(json.dumps(asdict(result), indent=2, default=str))
        return

    table = Table(title=f"Project gate: {result.project_id}")
    table.add_column("Signal")
    table.add_column("Result")
    table.add_row("Verdict", "ACCEPT" if result.accepted else "REJECT")
    table.add_row("Rejected by", result.rejected_by)
    oracle = "reproduces" if result.oracle_ok else "BROKEN"
    poc = "blocked" if result.security_pass else "succeeds"
    behavior = "pass" if result.behavior_pass else "fail"
    checker = "clear" if result.checker_pass else "blocking"
    table.add_row("Oracle", f"exit {result.oracle_exit} / {oracle}")
    table.add_row("PoC", f"exit {result.poc_exit} / {poc}")
    table.add_row("Functional", f"exit {result.behavior_exit} / {behavior}")
    table.add_row("Checker", f"{result.checker_tool} / {checker}")
    table.add_row("Files", str(result.total_files))
    table.add_row("Lines", str(result.total_lines))
    table.add_row("Isolation", result.isolation)
    console.print(table)
    if result.reasons:
        console.print("\n[bold]Reasons[/bold]")
        for reason in result.reasons:
            console.print(f"  - {reason}")
    if result.findings:
        console.print("\n[bold]Findings[/bold]")
        for finding in result.findings:
            location = f" {finding.path}" if finding.path else ""
            line = f":{finding.line}" if finding.line else ""
            console.print(
                f"  {finding.rule_id} {finding.cwe}{location}{line}: {finding.message}"
            )
    console.print(f"\n[dim]{result.isolation_warning}[/dim]")


@app.command()
def show(
    task_id: Annotated[str, typer.Argument(help="Task id, for example cmd_runner.")],
    pack: Annotated[Path, typer.Option("--pack", help="Security pack directory.")] = Path(
        "security_workers"
    ),
    candidate: Annotated[
        str | None,
        typer.Option("--candidate", help="Also show one candidate implementation."),
    ] = None,
) -> None:
    """Print the vulnerable code, exploit, functional test, and candidates."""
    task = load_task(pack / task_id)
    console.print(
        Panel.fit(
            f"[bold]{task.title}[/bold]\n{task.cwe} · {task.task_id}\n\n{task.summary}",
            title="Task",
        )
    )

    sections: list[tuple[str, Path]] = [
        ("Vulnerable implementation", task.vulnerable),
        ("Exploit", task.poc),
        ("Functional test", task.functional),
    ]
    if candidate:
        selected = find_candidate(task, candidate)
        sections.append((f"Candidate: {selected.name}", task.root / selected.path))

    for label, path in sections:
        console.print(f"\n[bold]{label}[/bold] [dim]{_relative(path)}[/dim]")
        console.print(
            Syntax(
                path.read_text(encoding="utf-8"),
                "python",
                line_numbers=True,
                word_wrap=True,
            )
        )

    table = Table(title="Candidates")
    table.add_column("Name")
    table.add_column("Kind")
    table.add_column("Path", overflow="fold")
    table.add_column("Expected")
    for item in task.candidates:
        expected = "accept" if item.kind in {"gold", "benign"} else "reject"
        table.add_row(
            item.name,
            item.kind,
            _relative(task.root / item.path),
            expected,
        )
    console.print(table)


@app.command()
def verify(
    task_id: Annotated[str, typer.Argument(help="Task id, for example cmd_runner.")],
    candidate_name: Annotated[str, typer.Argument(help="Candidate name.")],
    pack: Annotated[Path, typer.Option("--pack", help="Security pack directory.")] = Path(
        "security_workers"
    ),
    checker: Annotated[
        str,
        typer.Option("--checker", help="Primary checker: acv-rules or bandit."),
    ] = "acv-rules",
    as_json: Annotated[bool, typer.Option("--json", help="Print the full result as JSON.")] = False,
) -> None:
    """Run the deterministic gate only. No model and no API key."""
    task = load_task(pack / task_id)
    candidate = find_candidate(task, candidate_name)
    result = evaluate_candidate(task, candidate, primary_checker=_checker(checker))

    if as_json:
        console.print_json(json.dumps(asdict(result), indent=2))
    else:
        table = Table(title=f"Gate: {result.task_id}/{result.name}")
        table.add_column("Signal")
        table.add_column("Result")
        table.add_row("Gate verdict", "ACCEPT" if result.accepted else "REJECT")
        table.add_row("Ground truth", "ACCEPT" if result.expected_accepted else "REJECT")
        table.add_row("Correct", "yes" if result.correct else "NO")
        table.add_row(
            "PoC",
            f"exit {result.poc_exit} / "
            f"{'blocked' if result.security_pass else 'succeeded'}",
        )
        table.add_row(
            "Functional",
            f"exit {result.behavior_exit} / "
            f"{'pass' if result.behavior_pass else 'fail'}",
        )
        table.add_row(
            "Checker",
            f"{result.checker_tool} / "
            f"{'pass' if result.checker_pass else 'blocking findings'}",
        )
        table.add_row("Rejected by", result.rejected_by)
        console.print(table)
        console.print(f"\n[bold]PoC output[/bold]\n{result.poc_output or '(empty)'}")
        console.print(
            f"\n[bold]Functional output[/bold]\n{result.behavior_output or '(empty)'}"
        )
        if result.findings:
            console.print("\n[bold]Checker findings[/bold]")
            for finding in result.findings:
                line = f" line {finding.line}" if finding.line else ""
                console.print(
                    f"  {finding.rule_id} {finding.cwe}{line}: {finding.message}"
                )
        if result.reasons:
            console.print("\n[bold]Reasons[/bold]")
            for reason in result.reasons:
                console.print(f"  - {reason}")

    if not result.correct:
        raise typer.Exit(1)


@app.command()
def review(
    task: Annotated[str, typer.Argument(help="Task id, for example cmd_runner.")],
    candidate: Annotated[str, typer.Argument(help="Candidate name, for example sh_c_filter.")],
    pack: Annotated[Path, typer.Option("--pack", help="Security pack directory.")] = Path(
        "security_workers"
    ),
    model: Annotated[
        str | None,
        typer.Option("--model", help="Override the Groq model."),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print the full result as JSON.")] = False,
) -> None:
    """Run a live model review and compare it with the deterministic gate."""
    try:
        result = review_by_id(pack, task, candidate, model=model)
    except (ReviewError, GroqError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc

    if as_json:
        console.print_json(result.model_dump_json())
        return

    verdict = result.review.verdict
    color = "green" if verdict == "likely_fixed" else "red"
    if verdict not in {"likely_fixed", "likely_vulnerable"}:
        color = "yellow"
    gate_match = "unknown" if result.llm_matches_gate is None else (
        "yes" if result.llm_matches_gate else "no"
    )
    truth_match = "unknown" if result.llm_matches_truth is None else (
        "yes" if result.llm_matches_truth else "no"
    )
    table = Table(title=f"Live review: {result.task_id}/{result.candidate}")
    table.add_column("Signal")
    table.add_column("Result")
    table.add_row("AI verdict", f"[{color}]{verdict}[/{color}]")
    table.add_row("Confidence", f"{result.review.confidence:.0%}")
    table.add_row("Gate accepted", "yes" if result.deterministic.accepted else "no")
    table.add_row("Ground truth", "accept" if result.deterministic.expected_accepted else "reject")
    table.add_row("AI matches gate", gate_match)
    table.add_row("AI matches truth", truth_match)
    table.add_row("Model", result.model)
    table.add_row("Latency", f"{result.latency_ms} ms")
    table.add_row("Tokens", str(result.usage.total_tokens))
    console.print(table)
    console.print(result.review.summary)
    if result.review.attack_path:
        console.print(f"\n[bold]Attack path[/bold]\n{result.review.attack_path}")
    if result.review.findings:
        console.print("\n[bold]Findings[/bold]")
        for finding in result.review.findings:
            line = f" line {finding.line}" if finding.line else ""
            console.print(
                f"  [bold]{finding.severity.upper()}[/bold] "
                f"{finding.cwe}{line}: {finding.issue}"
            )


@app.command()
def serve(
    host: Annotated[str, typer.Option("--host", help="Bind address.")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Port for the local app.")] = 8000,
) -> None:
    """Serve the interactive research console and API."""
    import uvicorn

    console.print(f"[bold]Research console:[/bold] http://{host}:{port}")
    console.print(f"[dim]OpenAPI docs: http://{host}:{port}/docs[/dim]")
    uvicorn.run("acv.server:app", host=host, port=port, reload=False)


@app.command("repo-list")
def repo_list(
    pack: Annotated[Path, typer.Option("--pack", help="Repo task pack directory.")] = Path(
        "repo_tasks"
    ),
) -> None:
    """List real-repository tasks that can be verified."""

    tasks = discover_repo_tasks(pack)
    if not tasks:
        console.print(f"[yellow]No repo tasks found under {pack}.[/yellow]")
        return

    table = Table(title=f"Real repositories ({len(tasks)})")
    table.add_column("Task")
    table.add_column("CWE")
    table.add_column("Repository")
    table.add_column("Commit")
    for task in tasks:
        table.add_row(
            task.task_id,
            task.cwe,
            task.repo_url.replace("https://github.com/", ""),
            task.commit[:12],
        )
    console.print(table)


@app.command("repo-verify")
def repo_verify(
    task_id: Annotated[str, typer.Argument(help="Repo task id.")],
    diff_file: Annotated[
        Path | None,
        typer.Option("--diff", help="Unified diff to apply inside the clone."),
    ] = None,
    checker: Annotated[
        str,
        typer.Option("--checker", help="Primary checker: acv-rules, bandit, or semgrep."),
    ] = "acv-rules",
    pack: Annotated[Path, typer.Option("--pack", help="Repo task pack directory.")] = Path(
        "repo_tasks"
    ),
    as_json: Annotated[bool, typer.Option("--json", help="Print the full result as JSON.")] = False,
) -> None:
    """Clone a real repository and judge a patch against it.

    With no ``--diff`` the run reports the baseline: it proves the PoC
    reproduces the vulnerability and that the repository's own tests pass.
    """

    try:
        spec = find_repo_task(task_id, pack)
    except RepoIntakeError as exc:
        raise typer.BadParameter(str(exc)) from exc

    diff = ""
    if diff_file is not None:
        try:
            diff = diff_file.read_text(encoding="utf-8")
        except OSError as exc:
            raise typer.BadParameter(f"could not read diff: {exc}") from exc

    with console.status(f"cloning {spec.repo_url} at {spec.commit[:12]} ..."):
        try:
            result = evaluate_repo(spec, diff=diff, checker=checker)
        except RepoIntakeError as exc:
            raise typer.BadParameter(str(exc)) from exc

    if as_json:
        console.print_json(json.dumps(asdict(result), indent=2, default=str))
        return

    table = Table(title=f"Real repo gate: {result.task_id}")
    table.add_column("Signal")
    table.add_column("Result")
    table.add_row("Verdict", "ACCEPT" if result.accepted else "REJECT")
    table.add_row("Rejected by", result.rejected_by)
    table.add_row("Repository", result.repo_url.replace("https://github.com/", ""))
    table.add_row("Commit", result.commit[:12])
    table.add_row("Oracle", f"exit {result.oracle_exit} / {result.oracle_verdict}")
    table.add_row("PoC", f"exit {result.poc_exit} / {result.poc_verdict}")
    behavior = "pass" if result.behavior_pass else "fail"
    table.add_row("Functional", f"exit {result.behavior_exit} / {behavior}")
    checker_state = "clear" if result.checker_pass else "blocking"
    table.add_row("Checker", f"{result.checker_tool} / {checker_state}")
    table.add_row("Files", str(result.total_files))
    table.add_row("Lines", str(result.total_lines))
    table.add_row("Changed", ", ".join(result.changed_files) or "none")
    table.add_row("Isolation", result.isolation)
    console.print(table)

    if result.reasons:
        console.print("\n[bold]Reasons[/bold]")
        for reason in result.reasons:
            console.print(f"  - {reason}")
    console.print(f"\n[dim]{result.isolation_warning}[/dim]")


@app.command("repo-stale")
def repo_stale(
    pack: Annotated[Path, typer.Option("--pack", help="Repo task pack directory.")] = Path(
        "repo_tasks"
    ),
    only: Annotated[str, typer.Option("--only", help="Check a single task id.")] = "",
    as_json: Annotated[bool, typer.Option("--json", help="Print the report as JSON.")] = False,
) -> None:
    """Check whether each known vulnerability is still present on live code.

    This is the gate in front of any contribution. A pull request is only worth
    opening when the attack still reproduces on the repository's default branch.
    """

    tasks = discover_repo_tasks(pack)
    if only:
        tasks = [task for task in tasks if task.task_id == only]
    if not tasks:
        raise typer.BadParameter("no repo tasks found")

    reports = []
    with console.status("probing live default branches ..."):
        for spec in tasks:
            reports.append(probe_default_branch(spec))

    if as_json:
        console.print_json(json.dumps([asdict(r) for r in reports], indent=2, default=str))
        return

    table = Table(title="Live status of known vulnerabilities")
    table.add_column("Task")
    table.add_column("CWE")
    table.add_column("Live status")
    table.add_column("Branch")
    table.add_column("HEAD")
    for report in reports:
        status = {
            "unfixed": "[red]UNFIXED[/red]",
            "fixed": "[green]fixed[/green]",
            "unknown": "[yellow]unknown[/yellow]",
        }[report.status]
        table.add_row(
            report.task_id, report.cwe, status, report.branch, report.head_commit[:12]
        )
    console.print(table)

    live = [report for report in reports if report.is_live]
    console.print()
    if live:
        console.print(
            f"[bold red]{len(live)} task(s) still reproduce on live code[/bold red] "
            "and are candidates for a contribution:"
        )
        for report in live:
            console.print(f"  - {report.task_id} ({report.cwe}): {report.detail}")
        console.print(
            "\n[dim]Build a reviewable branch with: uv run acv repo-harden <task>[/dim]"
        )
    else:
        console.print(
            f"[bold green]None of the {len(reports)} known vulnerabilities reproduce on "
            "live code.[/bold green] Do not open pull requests for them."
        )
    unknown = [report for report in reports if report.status == "unknown"]
    if unknown:
        console.print(
            f"\n[yellow]{len(unknown)} task(s) could not reach a verdict[/yellow]; "
            "treat them as unproven, not as fixed."
        )


@app.command("repo-harden")
def repo_harden(
    task_id: Annotated[str, typer.Argument(help="Repo task id with a live vulnerability.")],
    diff_file: Annotated[
        Path | None,
        typer.Option("--diff", help="Unified diff to apply to the default branch."),
    ] = None,
    clone: Annotated[
        Path | None,
        typer.Option("--clone", help="Directory to keep the clone in (default: /tmp)."),
    ] = None,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="Build even when live status is unknown or fixed. Never bypasses the gate.",
        ),
    ] = False,
    pack: Annotated[Path, typer.Option("--pack", help="Repo task pack directory.")] = Path(
        "repo_tasks"
    ),
) -> None:
    """Build a reviewable hardening branch for a live vulnerability.

    Nothing is pushed and no remote is touched. The command writes a local
    branch plus a pull-request body for you to read before you push anything.
    """

    try:
        spec = find_repo_task(task_id, pack)
    except RepoIntakeError as exc:
        raise typer.BadParameter(str(exc)) from exc

    if diff_file is None:
        raise typer.BadParameter(
            "supply --diff with the patch to build a branch from; nothing is "
            "generated automatically"
        )
    try:
        diff = diff_file.read_text(encoding="utf-8")
    except OSError as exc:
        raise typer.BadParameter(f"could not read diff: {exc}") from exc

    try:
        with console.status("probing live code and building the branch ..."):
            report = build_hardening_branch(spec, diff=diff, clone_dir=clone, force=force)
    except HardenRefused as exc:
        console.print("[bold red]Refused[/bold red]")
        console.print(f"  {exc}")
        raise typer.Exit(code=1) from exc

    console.print(
        Panel.fit(
            f"[bold]{report.title}[/bold]\n{report.cwe} · {report.task_id}",
            title="Hardening branch ready",
        )
    )
    table = Table()
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Branch", report.branch)
    table.add_row("Clone", report.clone_dir)
    table.add_row("Base commit", report.commit[:12])
    table.add_row("Files changed", ", ".join(report.changed_files))
    if report.gate is not None:
        table.add_row("Attack after patch", report.gate.attack)
        table.add_row("Own test suite", report.gate.behavior)
        table.add_row("New findings", report.gate.checker)
    table.add_row("PR body", report.pull_request_path)
    console.print(table)

    for note in report.notes:
        console.print(f"[dim]note: {note}[/dim]")

    console.print(
        "\n[bold]Nothing has been pushed.[/bold] Review the patch and the PR body, "
        "then push yourself:\n"
        f"  cd {report.clone_dir}\n"
        f"  git push <your-fork> {report.branch}"
    )


def main() -> None:
    app()

if __name__ == "__main__":
    main()
