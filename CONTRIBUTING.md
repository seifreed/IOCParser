# Contributing to IOCParser

Thank you for your interest in contributing to IOCParser! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Contributions](#making-contributions)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Submitting Changes](#submitting-changes)

## Code of Conduct

By participating in this project, you agree to abide by our code of conduct:

- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on constructive criticism
- Accept feedback gracefully
- Prioritize the project's best interests

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/iocparser.git
   cd iocparser
   ```
3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/seifreed/iocparser.git
   ```

## Development Setup

### Prerequisites

- Python 3.8 or higher
- pip and virtualenv
- Git

### Setting Up Your Environment

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install the package in development mode:
   ```bash
   pip install -e .
   ```

3. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

4. Install pre-commit hooks:
   ```bash
   pre-commit install
   ```

## Making Contributions

### Types of Contributions

We welcome various types of contributions:

- **Bug Fixes**: Fix issues reported in GitHub Issues
- **New Features**: Add new IOC extraction capabilities
- **Performance Improvements**: Optimize existing code
- **Documentation**: Improve or add documentation
- **Tests**: Add or improve test coverage
- **Refactoring**: Improve code structure and readability

### Workflow

1. **Create a Branch**: 
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-number
   ```

2. **Make Your Changes**: Follow our coding standards (see below)

3. **Write/Update Tests**: Ensure your changes are tested

4. **Run Tests Locally**:
   ```bash
   pytest tests/
   ```

5. **Check Code Quality**:
   ```bash
   black iocparser/
   flake8 iocparser/
   mypy iocparser/
   ```

6. **Commit Your Changes**:
   ```bash
   git add .
   git commit -m "feat: add support for extracting X IOC type"
   ```

### Commit Message Format

We use conventional commits format:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Code style changes (formatting, etc.)
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `test:` Test additions or changes
- `chore:` Maintenance tasks

Examples:
```
feat: add extraction support for MITRE ATT&CK IDs
fix: correct IPv6 regex pattern matching
docs: update README with new IOC types
perf: optimize domain extraction for large files
```

## Coding Standards

### Python Style Guide

We follow PEP 8 with some modifications:

- Maximum line length: 100 characters
- Use type hints for all function signatures
- Use docstrings for all public functions and classes

### Code Formatting

We use `black` for automatic code formatting:

```bash
black --line-length 100 iocparser/
```

### Type Hints

All new code should include type hints:

```python
from typing import List, Dict, Optional

def extract_iocs(text: str, defang: bool = True) -> Dict[str, List[str]]:
    """
    Extract IOCs from text.
    
    Args:
        text: Input text to process
        defang: Whether to defang extracted IOCs
        
    Returns:
        Dictionary mapping IOC types to lists of IOCs
    """
    pass
```

### Docstrings

Use Google-style docstrings:

```python
def function_name(param1: str, param2: int) -> bool:
    """
    Brief description of the function.
    
    More detailed description if needed.
    
    Args:
        param1: Description of param1
        param2: Description of param2
        
    Returns:
        Description of return value
        
    Raises:
        ValueError: When invalid input is provided
    """
    pass
```

## Testing

### Writing Tests

- Write tests for all new functionality
- Place tests in the `tests/` directory
- Use descriptive test names
- Include edge cases and error conditions

Example test:

```python
def test_extract_md5_valid():
    """Test extraction of valid MD5 hashes."""
    extractor = IOCExtractor()
    text = "Hash: 5f4dcc3b5aa765d61d8327deb882cf99"
    result = extractor.extract_md5(text)
    assert len(result) == 1
    assert "5f4dcc3b5aa765d61d8327deb882cf99" in result
```

### Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=iocparser --cov-report=term-missing

# Run specific test file
pytest tests/test_extractors.py

# Run tests in verbose mode
pytest tests/ -v
```

### Performance Testing

For performance-critical changes:

```bash
pytest tests/test_performance.py --benchmark-only
```

## Documentation

### Code Documentation

- Add docstrings to all public functions and classes
- Update existing docstrings when changing functionality
- Include examples in docstrings for complex functions

### README Updates

Update the README.md when:
- Adding new IOC types
- Changing command-line interface
- Adding new features
- Changing installation requirements

### API Documentation

For significant API changes, update the documentation:

```bash
# Generate API documentation
sphinx-build -b html docs/ docs/_build/
```

## Submitting Changes

### Pull Request Process

1. **Update Your Fork**:
   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

2. **Rebase Your Branch**:
   ```bash
   git checkout your-branch
   git rebase main
   ```

3. **Push to Your Fork**:
   ```bash
   git push origin your-branch
   ```

4. **Create Pull Request**:
   - Go to GitHub and create a pull request
   - Fill in the PR template
   - Link related issues
   - Ensure CI checks pass

### PR Requirements

Before submitting a PR, ensure:

- [ ] All tests pass
- [ ] Code follows style guidelines
- [ ] Documentation is updated
- [ ] Commit messages follow convention
- [ ] PR description clearly explains changes
- [ ] Related issues are linked

### Review Process

1. Maintainers will review your PR
2. Address any feedback or requested changes
3. Once approved, your PR will be merged

## Adding New IOC Types

When adding support for new IOC types:

1. **Add Regex Pattern** in `extractor.py`:
   ```python
   self.patterns['new_ioc_type'] = re.compile(r'pattern')
   ```

2. **Add Extraction Method**:
   ```python
   def extract_new_ioc_type(self, text: str) -> List[str]:
       """Extract new IOC type from text."""
       return self._extract_pattern(text, 'new_ioc_type')
   ```

3. **Update `extract_all` Method**:
   ```python
   ('new_ioc_type', self.extract_new_ioc_type),
   ```

4. **Add Tests**:
   ```python
   def test_extract_new_ioc_type():
       # Test implementation
   ```

5. **Update Documentation**:
   - Add to README.md features list
   - Update API documentation

## Questions and Support

If you have questions:

1. Check existing [issues](https://github.com/seifreed/iocparser/issues)
2. Search the [documentation](https://github.com/seifreed/iocparser#readme)
3. Create a new issue with the question label

## License

By contributing to IOCParser, you agree that your contributions will be licensed under the MIT License.

## Recognition

Contributors will be recognized in:
- The project's contributors list
- Release notes for significant contributions
- The AUTHORS file (for major contributors)

Thank you for contributing to IOCParser!