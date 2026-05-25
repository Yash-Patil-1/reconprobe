# =============================================================================
# ReconProbe — Makefile
# =============================================================================

.PHONY: help install dev install-dev test lint typecheck clean build publish \
        docker-build docker-run format check all

PACKAGE := reconprobe
PYTHON := python3
VERSION := $(shell $(PYTHON) -c "import reconprobe; print(reconprobe.__version__)" 2>/dev/null || echo "unknown")

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install package and dependencies
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e "."

install-dev: ## Install development dependencies
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -e ".[dev]"
	$(PYTHON) -m pip install pytest pytest-asyncio flake8 mypy httpx

test: ## Run test suite
	$(PYTHON) -m pytest tests/ -v --tb=short -q

test-coverage: ## Run tests with coverage report
	$(PYTHON) -m pytest tests/ -v --tb=short --cov=$(PACKAGE) --cov-report=term-missing

lint: ## Run flake8 linter
	flake8 reconprobe/ tests/ --max-line-length=120 --extend-ignore=E203,W503

typecheck: ## Run mypy type checker
	mypy reconprobe/ --ignore-missing-imports --no-strict-optional || true

check: lint typecheck test ## Run all checks (lint + typecheck + test)

clean: ## Clean build artifacts and cache
	rm -rf build/ dist/ *.egg-info .pytest_cache __pycache__
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	rm -rf .mypy_cache .ruff_cache

build: clean ## Build source and wheel distributions
	$(PYTHON) -m pip install --upgrade build
	$(PYTHON) -m build

publish: build ## Build and publish to PyPI
	$(PYTHON) -m pip install --upgrade twine
	$(PYTHON) -m twine upload dist/*

publish-test: build ## Build and publish to TestPyPI
	$(PYTHON) -m pip install --upgrade twine
	$(PYTHON) -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*

docker-build: ## Build Docker image
	docker build -t reconprobe:$(VERSION) -t reconprobe:latest .

docker-run: ## Run Docker container (example scan)
	docker run --rm reconprobe:latest example.com -o /reports

format: ## Format code with autopep8 (basic cleanup)
	$(PYTHON) -m autopep8 --in-place --recursive --max-line-length=120 \
		--aggressive reconprobe/ tests/ || echo "Install autopep8: pip install autopep8"
