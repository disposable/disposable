# Makefile for disposable email domain generator

.PHONY: all format check validate test test-unit test-integration test-sources test-all help reformat-ruff fix-ruff fix vulture complexity xenon bandit pyright

# Default target: runs format and check
all: validate test-unit

# Format the code using ruff
format:
	ruff format --check --diff .

reformat-ruff:
	ruff format .

# Check the code using ruff
check:
	ruff check .

fix-ruff:
	ruff check . --fix

fix: reformat-ruff fix-ruff
	@echo "Updated code."

vulture:
	vulture src --exclude .venv,__pycache__ --min-confidence 80

complexity:
	radon cc src -a -nc

xenon:
	-xenon -b C -m C -a C src || true

bandit:
	bandit -c pyproject.toml -r src

pyright:
	pyright

test:
	pytest

test-unit:
	pytest tests/unit/ --cov-fail-under=50

test-integration:
	pytest -m integration

test-sources:
	pytest tests/integration/test_sources.py -v --tb=short

test-all:
	pytest --tb=short

# Validate the code (format + check)
validate: format check bandit pyright vulture complexity xenon
	@echo "Validation passed. Your code is ready to push."

# Help target
help:
	@echo "Available targets:"
	@echo "  all           - Run validation and unit tests (default)"
	@echo "  format        - Check code formatting with ruff"
	@echo "  reformat-ruff - Format code with ruff"
	@echo "  check         - Run ruff linting"
	@echo "  fix-ruff      - Auto-fix ruff issues"
	@echo "  fix           - Run reformat-ruff and fix-ruff"
	@echo "  vulture       - Run dead code detection"
	@echo "  complexity    - Run complexity analysis"
	@echo "  xenon         - Run xenon complexity check"
	@echo "  bandit        - Run security analysis"
	@echo "  pyright       - Run type checking"
	@echo "  test          - Run all tests"
	@echo "  test-unit     - Run unit tests only"
	@echo "  test-integration - Run integration tests only"
	@echo "  test-sources  - Run source verification tests (network required)"
	@echo "  test-all      - Run all tests with short traceback"
	@echo "  validate      - Run all validation checks"
	@echo "  help          - Show this help message"
