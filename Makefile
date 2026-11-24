.PHONY: sync test lint format audit demo list show verify tools qualify serve projects project-demo

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

projects:
	uv run acv projects

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

project-demo: projects
	uv run acv verify-project doc_portal --candidate gold
	uv run acv verify-project doc_portal --candidate absolute_only
	uv run acv verify-project gitpython_cve_2022_24439 --candidate gold
	uv run acv verify-project gitpython_cve_2022_24439 --candidate clone_only

demo: sync list show verify tools
