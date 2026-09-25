.PHONY: lint format typecheck test check

lint:
	uv run ruff check
	uv run ruff format --check

format:
	uv run ruff check --fix
	uv run ruff format

typecheck:
	uv run pyright

test:
	uv run pytest --cov --cov-report=term-missing

check: lint typecheck test
