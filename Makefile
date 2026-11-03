.PHONY: sync test lint format audit demo

sync:
	uv sync --all-extras

test:
	uv run pytest

lint:
	uv run ruff check .
	uv run mypy src

format:
	uv run ruff format src tests scripts
	uv run ruff check --fix src tests scripts

audit:
	uv run acv audit

demo: sync audit
	@echo "Open presentation/index.html"
