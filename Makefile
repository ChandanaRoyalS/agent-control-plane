.DEFAULT_GOAL := help
.PHONY: help install check fmt lint types test cov clean

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-10s\033[0m %s\n", $$1, $$2}'

install:  ## Install dependencies and git hooks
	uv sync --all-groups
	uv run pre-commit install
	# Windows-hosted downloads arrive marked executable; ignore the bit entirely.
	git config core.fileMode false

check: lint types test  ## Everything CI runs, in the same order

fmt:  ## Apply formatting and safe autofixes
	uv run ruff format .
	uv run ruff check --fix .

lint:  ## Lint and verify formatting
	uv run ruff check .
	uv run ruff format --check .

types:  ## Strict type check
	uv run mypy

test:  ## Run the test suite with coverage
	uv run pytest

cov:  ## Open the HTML coverage report
	uv run pytest --cov-report=html
	@echo "open htmlcov/index.html"

clean:  ## Remove caches and build artifacts
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage coverage.xml
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
