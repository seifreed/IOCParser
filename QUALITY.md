# IOCParser Code Quality Guide

This project is configured with comprehensive code quality tools to maintain 100% code standards.

## 🚀 Quick Setup

```bash
# Run the automated setup script
./setup_quality.sh

# Or manually:
make install-dev
make pre-commit
```

## 📋 Quality Tools Overview

### Pre-commit Hooks
The project uses extensive pre-commit hooks that run automatically before each commit:

| Tool | Purpose | Configuration |
|------|---------|--------------|
| **Ruff** | Fast Python linter & formatter (replaces Black, isort, flake8) | `pyproject.toml` |
| **MyPy** | Static type checking | `pyproject.toml` |
| **Bandit** | Security vulnerability scanning | `pyproject.toml` |
| **Pylint** | Advanced code analysis | `pyproject.toml` |
| **Safety** | Dependency vulnerability checking | `.pre-commit-config.yaml` |
| **detect-secrets** | Prevent secrets in code | `.secrets.baseline` |

### Additional Tools

- **pytest** - Testing framework with coverage
- **pytest-cov** - Code coverage reporting
- **pytest-benchmark** - Performance benchmarking
- **pip-audit** - Dependency auditing

## 🔧 Development Workflow

### 1. Before Starting Development

```bash
# Activate virtual environment
source venv/bin/activate

# Update pre-commit hooks
pre-commit autoupdate

# Run all checks
make check-all
```

### 2. During Development

```bash
# Format code automatically
make format

# Run linters
make lint

# Run tests
make test

# Run security checks
make security
```

### 3. Before Committing

```bash
# Run pre-commit hooks manually
pre-commit run --all-files

# Or use make
make pre-commit
```

## 📊 Quality Metrics

### Code Coverage Target: 100%

```bash
# Generate coverage report
make test

# View HTML report
open htmlcov/index.html
```

### Type Coverage Target: 100%

```bash
# Check type coverage
mypy iocparser --html-report mypy_report
open mypy_report/index.html
```

### Security Standards

```bash
# Run comprehensive security audit
make security
```

## 🛠️ Makefile Commands

| Command | Description |
|---------|-------------|
| `make help` | Show all available commands |
| `make install-dev` | Install with dev dependencies |
| `make test` | Run tests with coverage |
| `make lint` | Run all linters |
| `make format` | Auto-format code |
| `make security` | Run security checks |
| `make check-all` | Run all quality checks |
| `make pre-commit` | Run pre-commit hooks |
| `make quality-report` | Generate quality report |
| `make ci` | Run CI pipeline locally |

## 📈 Quality Standards

### Ruff Rules Enabled

- **E/W** - pycodestyle errors and warnings
- **F** - pyflakes
- **I** - isort
- **B** - flake8-bugbear
- **C4** - flake8-comprehensions
- **UP** - pyupgrade
- **S** - flake8-bandit (security)
- **N** - pep8-naming
- **PTH** - flake8-use-pathlib
- **SIM** - flake8-simplify
- **And many more...**

### Code Complexity Limits

- Max line length: 100
- Max cyclomatic complexity: 10
- Max function arguments: 7
- Max branches: 15
- Max returns: 6
- Max statements: 50

### Type Checking Configuration

```python
# MyPy strict settings
warn_return_any = true
warn_unused_configs = true
no_implicit_optional = true
warn_redundant_casts = true
warn_unused_ignores = true
warn_unreachable = true
strict_equality = true
```

## 🔍 Quality Checks Details

### 1. Linting (Ruff)

Ruff combines multiple tools:
- Black (formatting)
- isort (import sorting)
- flake8 (style guide)
- pylint (code analysis)
- bandit (security)
- And 20+ other linters

```bash
# Check for issues
ruff check iocparser

# Auto-fix issues
ruff check --fix iocparser

# Format code
ruff format iocparser
```

### 2. Type Checking (MyPy)

```bash
# Run type checking
mypy iocparser

# Generate HTML report
mypy iocparser --html-report mypy_report
```

### 3. Security Scanning (Bandit)

```bash
# Run security scan
bandit -r iocparser -ll

# Generate JSON report
bandit -r iocparser -f json -o bandit-report.json
```

### 4. Dependency Auditing

```bash
# Check for known vulnerabilities
safety check
pip-audit

# Update dependencies
make update-deps
```

## 📝 Pre-commit Hook Configuration

The `.pre-commit-config.yaml` includes:

1. **File Fixes**
   - Trailing whitespace removal
   - End-of-file fixing
   - Large file checking
   - Merge conflict detection

2. **Python Quality**
   - Ruff linting and formatting
   - MyPy type checking
   - Bandit security scanning
   - Pylint code analysis
   - Docstring checking

3. **Security**
   - Secret detection
   - Private key detection
   - Dependency vulnerability scanning

4. **Documentation**
   - Markdown linting
   - YAML validation

## 🎯 Achieving 100% Quality

### Step 1: Run Full Check

```bash
make check-all
```

### Step 2: Fix Any Issues

```bash
# Auto-fix what's possible
make format

# Manual fixes for remaining issues
# Follow the error messages
```

### Step 3: Verify Coverage

```bash
# Test coverage
pytest tests/ --cov=iocparser --cov-report=term-missing

# Type coverage
mypy iocparser --strict
```

### Step 4: Security Audit

```bash
make security
```

### Step 5: Final Validation

```bash
# Run pre-commit on all files
pre-commit run --all-files

# If all passes, you have 100% quality!
```

## 🏆 Quality Badges

After achieving 100% quality, you can add these badges to your README:

```markdown
![Code Quality](https://img.shields.io/badge/code%20quality-100%25-brightgreen)
![Type Checked](https://img.shields.io/badge/type%20checked-mypy-blue)
![Security](https://img.shields.io/badge/security-bandit-yellow)
![Linted](https://img.shields.io/badge/linted-ruff-purple)
```

## 📚 Resources

- [Ruff Documentation](https://docs.astral.sh/ruff/)
- [MyPy Documentation](https://mypy.readthedocs.io/)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [Pre-commit Documentation](https://pre-commit.com/)

## 💡 Tips

1. **Use make commands** - They're configured with the right parameters
2. **Run pre-commit before pushing** - Catches issues early
3. **Keep dependencies updated** - Run `make update-deps` regularly
4. **Monitor coverage** - Aim for >90% test coverage
5. **Fix issues immediately** - Don't let technical debt accumulate

## 🐛 Troubleshooting

### Pre-commit hooks failing?
```bash
# Update hooks
pre-commit autoupdate

# Clear cache
pre-commit clean

# Reinstall
pre-commit install
```

### MyPy errors?
```bash
# Install type stubs
pip install types-requests types-setuptools

# Ignore specific modules in pyproject.toml
```

### Ruff conflicts?
```bash
# Check configuration
ruff check --show-settings

# Use --fix for auto-fixes
ruff check --fix iocparser
```

---

**Remember**: Quality is not just about passing checks, it's about writing maintainable, secure, and efficient code!