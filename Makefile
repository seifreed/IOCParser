.PHONY: help install install-dev clean test lint format security check-all pre-commit build docs

# Variables
PYTHON := python3
PIP := $(PYTHON) -m pip
PROJECT_NAME := iocparser
SRC_DIR := iocparser
TEST_DIR := tests

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(GREEN)IOCParser Development Commands$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(YELLOW)%-20s$(NC) %s\n", $$1, $$2}'

install: ## Install the package in production mode
	$(PIP) install -e .
	@echo "$(GREEN)✓ IOCParser installed successfully$(NC)"

install-dev: ## Install the package with development dependencies
	$(PIP) install -e ".[dev]"
	pre-commit install
	@echo "$(GREEN)✓ Development environment setup complete$(NC)"

clean: ## Clean build artifacts and cache files
	rm -rf build/ dist/ *.egg-info
	rm -rf .coverage htmlcov/ .pytest_cache/
	rm -rf .mypy_cache/ .ruff_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*~" -delete
	@echo "$(GREEN)✓ Cleaned build artifacts and cache files$(NC)"

test: ## Run all tests with coverage
	pytest $(TEST_DIR) -v --cov=$(SRC_DIR) --cov-report=term-missing --cov-report=html
	@echo "$(GREEN)✓ Tests completed. Coverage report available in htmlcov/index.html$(NC)"

test-fast: ## Run tests without coverage (faster)
	pytest $(TEST_DIR) -v
	@echo "$(GREEN)✓ Tests completed$(NC)"

test-benchmark: ## Run performance benchmark tests
	pytest $(TEST_DIR)/test_performance.py -v --benchmark-only
	@echo "$(GREEN)✓ Benchmark tests completed$(NC)"

lint: ## Run all linters (ruff, mypy, pylint)
	@echo "$(YELLOW)Running Ruff...$(NC)"
	ruff check $(SRC_DIR) $(TEST_DIR)
	@echo "$(YELLOW)Running MyPy...$(NC)"
	mypy $(SRC_DIR)
	@echo "$(YELLOW)Running Pylint...$(NC)"
	pylint $(SRC_DIR) || true
	@echo "$(GREEN)✓ Linting completed$(NC)"

format: ## Auto-format code with ruff
	ruff check --fix $(SRC_DIR) $(TEST_DIR)
	ruff format $(SRC_DIR) $(TEST_DIR)
	@echo "$(GREEN)✓ Code formatted$(NC)"

security: ## Run security checks (bandit, safety)
	@echo "$(YELLOW)Running Bandit security scan...$(NC)"
	bandit -r $(SRC_DIR) -ll
	@echo "$(YELLOW)Checking for known vulnerabilities in dependencies...$(NC)"
	safety check --json || true
	pip-audit || true
	@echo "$(GREEN)✓ Security checks completed$(NC)"

check-all: lint test security ## Run all checks (lint, test, security)
	@echo "$(GREEN)✓ All checks completed successfully$(NC)"

pre-commit: ## Run pre-commit hooks on all files
	pre-commit run --all-files
	@echo "$(GREEN)✓ Pre-commit hooks completed$(NC)"

pre-commit-update: ## Update pre-commit hooks to latest versions
	pre-commit autoupdate
	@echo "$(GREEN)✓ Pre-commit hooks updated$(NC)"

build: clean ## Build distribution packages
	$(PYTHON) -m build
	@echo "$(GREEN)✓ Distribution packages built in dist/$(NC)"

publish-test: build ## Publish to TestPyPI (for testing)
	$(PYTHON) -m twine upload --repository testpypi dist/*
	@echo "$(GREEN)✓ Published to TestPyPI$(NC)"

publish: build ## Publish to PyPI (requires credentials)
	$(PYTHON) -m twine upload dist/*
	@echo "$(GREEN)✓ Published to PyPI$(NC)"

docs: ## Generate API documentation
	pdoc --html --output-dir docs $(SRC_DIR) --force
	@echo "$(GREEN)✓ Documentation generated in docs/$(NC)"

quality-report: ## Generate comprehensive quality report
	@echo "$(YELLOW)Generating Quality Report...$(NC)"
	@echo "================================"
	@echo "Code Coverage:"
	@pytest $(TEST_DIR) --cov=$(SRC_DIR) --cov-report=term | grep TOTAL || true
	@echo ""
	@echo "Code Complexity:"
	@ruff check $(SRC_DIR) --select C901 --statistics || true
	@echo ""
	@echo "Type Coverage:"
	@mypy $(SRC_DIR) --html-report mypy_report 2>&1 | grep "Success:" || true
	@echo ""
	@echo "Security Issues:"
	@bandit -r $(SRC_DIR) -f json 2>/dev/null | python -m json.tool | grep '"issue_severity"' | wc -l | xargs echo "Total issues found:" || true
	@echo "$(GREEN)✓ Quality report completed$(NC)"

init-misp: ## Initialize MISP warning lists
	iocparser --init
	@echo "$(GREEN)✓ MISP warning lists initialized$(NC)"

example: ## Run IOCParser on the example file
	iocparser -f examples/sample_report.txt --json
	@echo "$(GREEN)✓ Example completed$(NC)"

dev-install: install-dev ## Alias for install-dev

setup: install-dev init-misp ## Complete setup (install + MISP lists)
	@echo "$(GREEN)✓ Complete setup finished$(NC)"

watch: ## Watch for file changes and run tests
	watchmedo shell-command --patterns="*.py" --recursive --command="make test-fast" $(SRC_DIR) $(TEST_DIR)

ci: ## Run CI pipeline locally
	@echo "$(YELLOW)Running CI pipeline...$(NC)"
	make lint
	make test
	make security
	@echo "$(GREEN)✓ CI pipeline completed successfully$(NC)"

stats: ## Show code statistics
	@echo "$(YELLOW)Code Statistics:$(NC)"
	@echo "Lines of code:"
	@find $(SRC_DIR) -name "*.py" -exec wc -l {} + | tail -1
	@echo "Number of Python files:"
	@find $(SRC_DIR) -name "*.py" | wc -l
	@echo "Number of tests:"
	@grep -r "def test_" $(TEST_DIR) | wc -l
	@echo "$(GREEN)✓ Statistics generated$(NC)"

update-deps: ## Update all dependencies to latest versions
	$(PIP) list --outdated
	$(PIP) install --upgrade pip setuptools wheel
	$(PIP) install --upgrade -r requirements.txt
	@echo "$(GREEN)✓ Dependencies updated$(NC)"

freeze: ## Freeze current dependencies
	$(PIP) freeze > requirements-freeze.txt
	@echo "$(GREEN)✓ Dependencies frozen to requirements-freeze.txt$(NC)"

validate: ## Validate project configuration files
	@echo "$(YELLOW)Validating configuration files...$(NC)"
	python -m py_compile $(SRC_DIR)/*.py $(SRC_DIR)/**/*.py
	python -c "import toml; toml.load('pyproject.toml')"
	yamllint .pre-commit-config.yaml
	yamllint .github/workflows/*.yml
	@echo "$(GREEN)✓ All configuration files are valid$(NC)"

# Default target
.DEFAULT_GOAL := help