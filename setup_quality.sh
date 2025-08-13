#!/bin/bash

# IOCParser Quality Setup Script
# This script sets up the project with all quality tools

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}IOCParser Quality Setup${NC}"
echo "========================"

# Function to print colored messages
print_status() {
    echo -e "${YELLOW}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Check Python version
print_status "Checking Python version..."
python_version=$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+')
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" = "$required_version" ]; then 
    print_success "Python $python_version is installed (>= $required_version required)"
else
    print_error "Python $python_version is too old. Please install Python >= $required_version"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    print_status "Creating virtual environment..."
    python3 -m venv venv
    print_success "Virtual environment created"
else
    print_success "Virtual environment already exists"
fi

# Activate virtual environment
print_status "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
print_status "Upgrading pip..."
pip install --upgrade pip setuptools wheel

# Install package with dev dependencies
print_status "Installing IOCParser with development dependencies..."
pip install -e ".[dev]"
print_success "IOCParser installed with development dependencies"

# Install additional quality tools
print_status "Installing additional quality tools..."
pip install ruff mypy bandit pylint safety pip-audit pre-commit
pip install types-requests types-setuptools types-colorama types-tqdm
print_success "Quality tools installed"

# Install pre-commit hooks
print_status "Installing pre-commit hooks..."
pre-commit install
pre-commit autoupdate
print_success "Pre-commit hooks installed"

# Create secrets baseline for detect-secrets
print_status "Creating secrets baseline..."
if command -v detect-secrets &> /dev/null; then
    detect-secrets scan --baseline .secrets.baseline
    print_success "Secrets baseline created"
else
    print_status "detect-secrets not found, skipping baseline creation"
fi

# Initialize MISP warning lists
print_status "Initializing MISP warning lists (this may take a moment)..."
python -m iocparser.main --init || {
    print_status "MISP initialization can be done later with: iocparser --init"
}

# Run initial quality checks
echo ""
echo -e "${GREEN}Running Initial Quality Checks${NC}"
echo "=============================="

# Ruff check
print_status "Running Ruff linter..."
ruff check iocparser --fix || true
ruff format iocparser || true
print_success "Ruff check completed"

# MyPy check
print_status "Running MyPy type checker..."
mypy iocparser --ignore-missing-imports || true
print_success "MyPy check completed"

# Bandit security check
print_status "Running Bandit security scanner..."
bandit -r iocparser -ll || true
print_success "Bandit check completed"

# Run tests
print_status "Running tests..."
pytest tests/ -v --cov=iocparser --cov-report=term-missing || true
print_success "Tests completed"

# Generate quality report
echo ""
echo -e "${GREEN}Quality Report${NC}"
echo "=============="

# Count lines of code
echo "Lines of code:"
find iocparser -name "*.py" -exec wc -l {} + | tail -1

# Count number of tests
echo "Number of tests:"
grep -r "def test_" tests/ | wc -l

# Check for TODOs
echo "TODOs in code:"
grep -r "TODO\|FIXME\|XXX" iocparser --include="*.py" | wc -l

echo ""
echo -e "${GREEN}Setup Complete!${NC}"
echo ""
echo "Available commands:"
echo "  make help        - Show all available make commands"
echo "  make test        - Run tests with coverage"
echo "  make lint        - Run all linters"
echo "  make format      - Auto-format code"
echo "  make security    - Run security checks"
echo "  make check-all   - Run all checks"
echo "  make pre-commit  - Run pre-commit hooks"
echo ""
echo "To activate the virtual environment in the future:"
echo "  source venv/bin/activate"
echo ""
echo "To run IOCParser:"
echo "  iocparser -f <file>"
echo ""
print_success "Project is ready for development with 100% quality tools!"