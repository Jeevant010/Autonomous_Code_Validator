.PHONY: sync test lint format audit demo list show verify tools qualify serve

sync:
	uv sync --all-extras

test:
	uv run pytest

lint:
	uv run ruff check .
	uv run mypy src

format:
	uv run ruff format src tests
	uv run ruff check --fix src tests

audit:
	uv run acv audit

list:
	uv run acv list

show:
	uv run acv show cmd_runner

verify:
	uv run acv verify cmd_runner semicolon_filter

tools:
	uv run acv tools

qualify:
	uv run acv qualify

serve:
	uv run acv serve

demo: sync list show verify tools
