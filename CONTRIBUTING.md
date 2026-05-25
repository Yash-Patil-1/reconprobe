# Contributing to ReconProbe

Thank you for considering contributing to ReconProbe! This document outlines the development workflow, coding standards, and pull request process.

## Table of Contents

- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)

## Development Setup

### Prerequisites

- **Python 3.10+** (3.12+ recommended)
- **Git**

### Clone and Install

```bash
git clone https://github.com/Yash-Patil-1/reconprobe.git
cd reconprobe

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Install Playwright browsers (for screenshots)
playwright install chromium
```

### Quick Commands

```bash
make test        # Run all tests
make lint        # Run ruff linter
make typecheck   # Run pyright type checker
make clean       # Clean build artifacts
make build       # Build distribution packages
```

## Project Structure

```
reconprobe/
├── reconprobe/           # Main package source
│   ├── __init__.py       # Package metadata + version
│   ├── __main__.py       # `python -m reconprobe` entry point
│   ├── cli.py            # CLI argument parser and orchestration
│   ├── runner.py         # Pipeline execution logic
│   ├── scanner.py        # Port scanning (Nmap wrapper)
│   ├── subdomain.py      # Subdomain discovery
│   ├── http_probe.py     # HTTP service probing
│   ├── vuln_scan.py      # CVE mapping + credential checking
│   ├── ssl_audit.py      # SSL/TLS certificate and protocol audit
│   ├── ...               # See README for full module list
├── tests/                # Test suite (mirrors module structure)
│   ├── test_scanner.py
│   ├── test_ssl_audit.py
│   └── ...
├── wordlists/            # Built-in wordlists (paths, subdomains)
├── pyproject.toml        # Project configuration
├── setup.py              # PyPI packaging
├── Makefile              # Common development tasks
└── Dockerfile            # Container build
```

## Coding Standards

### Python Style

- **Target Python version**: 3.10+ (type hints with `from __future__ import annotations`)
- **Formatter**: [Ruff](https://docs.astral.sh/ruff/)
- **Line length**: 120 characters
- **Naming conventions**:
  - `snake_case` for functions, methods, variables
  - `PascalCase` for classes
  - `UPPER_CASE` for constants
  - Prefix private functions/modules with `_`

### Type Hints

All public functions and methods **must** include type annotations:

```python
def match_cve_for_service(
    service_name: str,
    service_version: Optional[str] = None,
    banner: Optional[str] = None,
) -> list[CVEInfo]:
    ...
```

Use `Optional[T]` for nullable types, `list[T]` / `dict[K, V]` for collections.

### Imports

Organize imports in three blocks separated by a blank line:
1. Standard library (`os`, `sys`, `asyncio`, etc.)
2. Third-party (`httpx`, `rich`, etc.)
3. Local (`reconprobe.*`)

### Docstrings

Use Google-style docstrings for public modules, classes, and functions:

```python
def audit_ssl(
    hostname: str,
    port: int = 443,
    check_protos: bool = True,
) -> SslAuditReport:
    """Run a full SSL/TLS audit against a host:port.

    Args:
        hostname: Target hostname.
        port: Target port (default 443).
        check_protos: Whether to check TLS protocol versions.

    Returns:
        SslAuditReport with all findings and a security grade.
    """
```

## Testing

### Running Tests

```bash
# Run all tests
make test

# Run specific test file
python -m pytest tests/test_ssl_audit.py -v

# Run tests with coverage
python -m pytest tests/ --cov=reconprobe --cov-report=term-missing

# Run tests matching a keyword
python -m pytest tests/ -k "ssl" -v
```

### Writing Tests

- **Framework**: pytest with pytest-asyncio
- **Location**: `tests/` directory, one file per module (e.g., `test_ssl_audit.py`)
- **Naming**: Test classes prefixed with `Test`, test methods prefixed with `test_`
- **Mocking**: Use `unittest.mock` (`MagicMock`, `AsyncMock`, `patch`)
- **Async tests**: Decorate with `@pytest.mark.asyncio`
- **Coverage goal**: Aim for 85%+ coverage on core modules

### Test Guidelines

1. **Test data structures** — Verify dataclass defaults and `to_dict()` output
2. **Test edge cases** — Empty inputs, connection errors, timeouts
3. **Test async mocks** — Use `MagicMock()` for sync writers, `AsyncMock()` for `drain()`, `read()`
4. **Avoid network calls** — All tests should mock network I/O
5. **Test both success and failure paths**

## Pull Request Process

1. **Fork and branch** — Create a feature branch from `main`:
   ```bash
   git checkout -b feat/your-feature-name
   ```

2. **Make changes** — Follow coding standards above

3. **Run tests** — Ensure all tests pass:
   ```bash
   make test
   ```

4. **Lint and type-check**:
   ```bash
   make lint
   make typecheck
   ```

5. **Commit** — Use conventional commit messages:
   ```
   feat: add subdomain brute-force concurrency control
   fix: handle timeout in SSL cert check
   docs: update README with API examples
   refactor: extract HTTP probe into separate module
   test: add edge case for empty scan results
   ```

6. **Push and open PR** — Push to your fork and open a PR against `main`

7. **Address review feedback** — Make requested changes and push updates

### PR Checklist

- [ ] Tests pass (`make test`)
- [ ] No lint warnings (`make lint`)
- [ ] Type checks pass (`make typecheck`)
- [ ] New code includes tests
- [ ] Public API documented with docstrings
- [ ] CHANGELOG.md updated (if applicable)

## Release Process

Releases are maintained by the project maintainers:

1. Bump version in `reconprobe/__init__.py` and `pyproject.toml`
2. Update `CHANGELOG.md` with the new version and changes
3. Create a git tag: `git tag v1.0.0`
4. Build distribution: `make build`
5. Publish to PyPI: `make publish`

## Code of Conduct

All contributors are expected to maintain a respectful and inclusive environment. Be constructive, patient, and kind.

---

_Last updated: May 2026_
