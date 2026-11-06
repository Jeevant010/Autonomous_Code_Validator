.PHONY: sync test lint format audit demo list show verify serve

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

serve:
	uv run acv serve

demo: sync list show verify
