# Contributing to TensorTrap

Thank you for your interest in contributing to TensorTrap! This document provides guidelines for contributing.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/TensorTrap.git`
3. Install development dependencies: `pip install -e ".[dev]"`
4. Create a feature branch: `git checkout -b feature/your-feature`

## Development Setup

```bash
# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=tensortrap --cov-report=html

# Run linting
ruff check src/
ruff format src/

# Run type checking
mypy src/
```

## Code Style

- We use [Ruff](https://github.com/astral-sh/ruff) for linting and formatting
- We use [mypy](https://mypy.readthedocs.io/) for type checking
- Line length: 100 characters
- Use type hints for all function signatures

## Testing

- All new features must include tests
- Maintain or improve test coverage
- Tests should be in the `tests/` directory
- Use pytest fixtures from `conftest.py`

### Writing Tests

```python
def test_feature_name(fixtures_dir):
    """Test description of what this tests."""
    # Arrange
    filepath = fixtures_dir / "test.pkl"

    # Act
    result = scan_file(filepath)

    # Assert
    assert result.is_safe
```

## Pull Request Process

1. Update documentation if needed
2. Add tests for new functionality
3. Ensure all tests pass: `pytest`
4. Ensure linting passes: `ruff check src/`
5. Update CHANGELOG.md with your changes
6. Submit a pull request with a clear description

## Adding New Scanners

To add support for a new file format:

1. Create a parser in `src/tensortrap/formats/`
2. Create a scanner in `src/tensortrap/scanner/`
3. Register the extension in `signatures/patterns.py`
4. Update the engine in `scanner/engine.py`
5. Add comprehensive tests
6. Update README.md

## Security Considerations

- Never execute pickle files during scanning
- Use `pickletools.genops()` for safe pickle analysis
- Validate all input before processing
- Report security issues privately to security@m2dynamics.us

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help newcomers get started

## Questions?

Open an issue or reach out to smichael@m2dynamics.us
