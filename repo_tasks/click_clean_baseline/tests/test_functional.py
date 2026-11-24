"""Functional test suite for Click clean baseline task.

Verifies essential CLI command parsing, parameter validation, option handling,
and runner execution.
"""

import click
from click.testing import CliRunner


def test_command_basic_invocation():
    @click.command()
    def hello():
        click.echo("Hello, World!")

    runner = CliRunner()
    result = runner.invoke(hello)
    assert result.exit_code == 0
    assert result.output.strip() == "Hello, World!"


def test_command_with_arguments_and_options():
    @click.command()
    @click.argument("name")
    @click.option("--count", default=1, type=int)
    def greet(name: str, count: int):
        for _ in range(count):
            click.echo(f"Hello, {name}!")

    runner = CliRunner()
    result = runner.invoke(greet, ["Alice", "--count", "3"])
    assert result.exit_code == 0
    lines = [line.strip() for line in result.output.strip().splitlines()]
    assert lines == ["Hello, Alice!", "Hello, Alice!", "Hello, Alice!"]


def test_command_validation_error():
    @click.command()
    @click.option("--port", type=click.IntRange(1, 65535))
    def serve(port: int):
        click.echo(f"Serving on port {port}")

    runner = CliRunner()
    result = runner.invoke(serve, ["--port", "99999"])
    assert result.exit_code != 0
    assert "is not in the range" in result.output


def test_group_subcommands():
    @click.group()
    def cli():
        pass

    @cli.command()
    def sub():
        click.echo("sub executed")

    runner = CliRunner()
    result = runner.invoke(cli, ["sub"])
    assert result.exit_code == 0
    assert "sub executed" in result.output
