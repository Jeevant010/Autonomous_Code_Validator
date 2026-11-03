"""Command-line interface for the validator."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .manifest import discover_tasks
from .report import aggregate, write_json, write_markdown, write_presentation_data
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


def main() -> None:
    app()


if __name__ == "__main__":
    main()
