"""Command-line interface for the validator."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .llm import GroqError
from .manifest import discover_tasks
from .report import aggregate, write_json, write_markdown, write_presentation_data
from .review import ReviewError, review_by_id
from .runner import CheckerName, run_audit

app = typer.Typer(
    name="acv",
    help="Two-sided verification for security changes.",
    no_args_is_help=True,
)
console = Console()


def _checker(value: str) -> CheckerName:
    if value not in {"acv-rules", "bandit"}:
        raise typer.BadParameter("checker must be acv-rules or bandit")
    return value  # type: ignore[return-value]


@app.command()
def version() -> None:
    """Print the validator version."""
    console.print(f"Autonomous Code Validator {__version__}")


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
    table.add_column("Candidates", justify="right")
    for task in tasks:
        table.add_row(task.task_id, task.cwe, task.title, str(len(task.candidates)))
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
    data_path: Annotated[
        Path,
        typer.Option("--data", help="Where to write the presentation data file."),
    ] = Path("presentation/data.js"),
) -> None:
    """Run the two-sided audit and write the reports."""
    primary = _checker(checker)
    selected = set(task) if task else None
    results = run_audit(pack, primary_checker=primary, task_ids=selected)
    write_json(json_path, results)
    write_markdown(markdown_path, results)
    write_presentation_data(data_path, results)
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
    console.print(f"Presentation data: {data_path}")


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
    """Serve the presentation and the live review API."""
    import uvicorn

    console.print(f"[bold]Live review:[/bold] http://{host}:{port}")
    console.print("[dim]The Groq key stays on the server. The browser never sees it.[/dim]")
    uvicorn.run("acv.server:app", host=host, port=port, reload=False)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
