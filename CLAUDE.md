# CLAUDE.md - AI Assistant Guide for aws-account

## Project Overview

**aws-account** is a CLI tool that prints AWS account and identity information to verify which AWS account/organization is currently in use. It extends the functionality of `aws sts get-caller-identity` by resolving account IDs to actual account names.

**Key Features:**
- Resolves AWS account IDs to account names via SSO
- Displays identity information (IAM users, assumed roles)
- Color-coded output for better readability
- Supports SSO and IAM authentication methods

**Current Version:** 0.2.5
**License:** Apache-2.0
**Repository:** https://github.com/rollwagen/aws-account

## Codebase Structure

```
aws-account/
├── aws_account/           # Main package directory
│   ├── cli.py            # Core CLI logic (270 lines)
│   └── test/             # Test directory
│       └── test_cli.py   # Unit tests
├── .github/              # GitHub Actions workflows
│   └── workflows/
│       ├── codeql-analysis.yml
│       ├── lint-python.yml
│       └── semgrep.yml
├── .trunk/               # Trunk tooling configuration
├── img/                  # Documentation images
├── pyproject.toml        # Poetry configuration & dependencies
├── poetry.lock           # Locked dependencies
├── .pre-commit-config.yaml
├── .flake8              # Flake8 linting configuration
├── .yamllint.yaml       # YAML linting configuration
├── .checkov.yaml        # Security scanning configuration
└── README.md            # User-facing documentation
```

### Key Files

- **aws_account/cli.py**: Single-file implementation containing:
  - `AWSAccount` and `AWSIdentity` NamedTuples
  - Main CLI logic using Click framework
  - AWS API interactions (STS, SSO, IAM, Organizations)
  - Custom colored logging

## Technology Stack

### Core Dependencies
- **Python:** >=3.11,<4
- **Click:** >=8.0.3 (CLI framework)
- **Boto3:** >=1.24.93 (AWS SDK)
- **Colorama:** >=0.4 (colored terminal output)
- **mypy-boto3-*** packages for type hints (sts, sso, iam, organizations)

### Development Tools
- **Poetry:** Dependency management and packaging
- **pytest:** Testing framework
- **flake8:** Linting (max line length: 120)
- **yapf:** Code formatting (PEP8 style, 120 column limit)
- **black:** Alternative formatter (currently commented out)
- **mypy:** Static type checking
- **pyre-check:** Additional type checking
- **isort:** Import sorting
- **pre-commit:** Git hooks for automated checks

### Security & Quality Tools
- **pip-audit:** Dependency vulnerability scanning
- **bandit:** Security issue detection
- **checkov:** Infrastructure-as-code security scanning
- **Semgrep:** Static analysis for security
- **CodeQL:** GitHub security analysis

## Development Setup

### Prerequisites
```bash
# Ensure Python 3.11+ is installed
python --version

# Install Poetry
curl -sSL https://install.python-poetry.org | python -
```

### Installation
```bash
# Clone the repository
git clone https://github.com/rollwagen/aws-account.git
cd aws-account

# Install dependencies
poetry install

# Activate virtual environment
poetry shell
```

### Running the Tool
```bash
# Via Poetry
poetry run aws-account

# Or after activating shell
aws-account

# With options
aws-account --debug
aws-account --version
```

### Running Tests
```bash
# Run all tests
poetry run pytest

# Run with verbose output
poetry run pytest -v

# Run specific test file
poetry run pytest aws_account/test/test_cli.py
```

### Running Linters
```bash
# Flake8 linting
poetry run flake8 --max-line-length 120 aws_account

# Format code with yapf
poetry run yapf -i -r aws_account

# Sort imports
poetry run isort aws_account

# Type checking with mypy
poetry run mypy aws_account

# Type checking with pyre
poetry run pyre check
```

### Pre-commit Hooks
```bash
# Install pre-commit hooks
pre-commit install

# Run hooks manually on all files
pre-commit run --all-files

# Run specific hook
pre-commit run flake8 --all-files
```

## Code Style and Standards

### Python Style
- **Line Length:** 120 characters maximum
- **Style Guide:** PEP8 (enforced by yapf and flake8)
- **Formatter:** yapf (primary), black (available but commented out)
- **Import Order:** Enforced by isort

### Type Hints
- **Required:** All functions should have type hints
- **Tools:** mypy and pyre-check for validation
- **AWS Types:** Use mypy-boto3-* stubs for AWS service types

### Naming Conventions
- **Functions:** `snake_case` (e.g., `_get_access_token`, `_print_identity_info`)
- **Classes:** `PascalCase` (e.g., `AWSAccount`, `AWSIdentity`)
- **Constants:** `UPPER_SNAKE_CASE` or `Final` variables (e.g., `color_key: Final`)
- **Private functions:** Prefix with underscore (e.g., `_init_logger`)

### Code Organization
- **NamedTuples:** Used for data structures (`AWSAccount`, `AWSIdentity`)
- **Enums:** Used for type classification (`CallerIdentityType`)
- **Global Logger:** Initialized once, used throughout (`log: Logger`)

## Testing

### Test Structure
- Tests located in `aws_account/test/`
- Uses pytest framework with unittest.mock
- Test file: `test_cli.py`

### Test Coverage Areas
1. **Data structures:** Basic NamedTuple functionality
2. **Identity types:** IAM user vs assumed role detection
3. **SSO token retrieval:** Mocked file system interactions

### Writing Tests
```python
from unittest import mock
from unittest.mock import patch
from aws_account.cli import AWSAccount, AWSIdentity

def test_new_feature():
    # Use patches for AWS API calls
    # Mock file system operations
    # Assert expected behavior
    pass
```

## CI/CD Pipeline

### GitHub Actions Workflows

#### 1. Python Linting (lint-python.yml)
- **Triggers:** Push/PR to `aws_account/**` or `.github/**`
- **Steps:**
  1. Checkout code
  2. Setup Python 3.11
  3. Install Poetry and dependencies
  4. Run flake8 with 120 char line length

#### 2. CodeQL Analysis (codeql-analysis.yml)
- Security vulnerability scanning
- Automated code analysis

#### 3. Semgrep (semgrep.yml)
- Additional security scanning
- Pattern-based code analysis

### Pre-commit Hooks (Local)
1. trailing-whitespace removal
2. end-of-file-fixer
3. flake8 linting
4. yapf formatting
5. isort import sorting
6. pip-audit security check
7. yamllint for YAML files

## Key Architecture Patterns

### Identity Detection Flow
```python
1. Get AWS credentials from botocore session
2. Call STS get_caller_identity
3. Parse ARN to determine identity type:
   - IAM User: arn:aws:iam::*:user/*
   - Assumed Role: arn:aws:sts::*:assumed-role/*
   - Federated User: arn:aws:sts::*:federated-user/*
4. For assumed roles: Query SSO for account details
5. For IAM users: Query IAM aliases or Organizations API
```

### Error Handling Strategy
- **UnauthorizedException:** SSO token expired, suggest `aws sso login`
- **ExpiredToken:** AWS credentials expired, exit with error
- **ClientError:** Log and exit gracefully
- **Missing credentials:** Detect early and exit with clear message

### Logging Levels
- **DEBUG:** Detailed execution flow, API responses, credentials (partial)
- **INFO:** General information messages
- **WARNING:** Non-fatal issues (e.g., missing SSO token)
- **ERROR:** Fatal errors requiring exit

## Common Development Tasks

### Adding a New Feature
1. Create feature branch: `git checkout -b feature/description`
2. Implement in `aws_account/cli.py`
3. Add type hints for all new functions
4. Write tests in `aws_account/test/test_cli.py`
5. Run linters: `poetry run flake8 aws_account`
6. Run tests: `poetry run pytest`
7. Format code: `poetry run yapf -i -r aws_account`
8. Commit with pre-commit hooks passing

### Fixing a Bug
1. Write a failing test that reproduces the bug
2. Fix the bug in `aws_account/cli.py`
3. Verify test passes
4. Run full test suite
5. Check linting and formatting

### Adding Dependencies
```bash
# Add runtime dependency
poetry add package-name

# Add dev dependency
poetry add --dev package-name

# Update pyproject.toml manually if needed
# Then run: poetry lock
```

### Updating Version
1. Update version in `pyproject.toml`
2. Ensure CHANGELOG is updated (if exists)
3. Create git tag: `git tag v0.2.6`
4. Push tag: `git push --tags`

## AWS API Usage Patterns

### Service Clients
```python
# Pattern used throughout codebase
session: Session = botocore.session.get_session()
sts: STSClient = session.create_client("sts")
sso_client: SSOClient = session.create_client("sso")
iam: IAMClient = session.create_client("iam")
org_client: OrganizationsClient = session.create_client("organizations")
```

### SSO Token Retrieval
- Reads from `~/.aws/sso/cache/`
- Looks for files starting with digit
- Parses JSON to extract `accessToken`
- Gracefully handles missing token

## Important Notes for AI Assistants

### Security Considerations
1. **Never log full credentials:** Only log partial tokens (first/last 5 chars)
2. **No secrets in code:** All credentials come from AWS SDK
3. **Use nosec for test tokens:** Mark test tokens with `# nosec` for bandit
4. **Validate SSO cache access:** Handle missing/invalid cache gracefully

### Code Quality Requirements
1. **All CI checks must pass:** flake8, CodeQL, Semgrep
2. **Type hints are mandatory:** Use mypy-boto3 stubs for AWS types
3. **Line length 120:** Enforced by flake8 and yapf
4. **No commented code:** Remove or uncomment before committing
5. **Pre-commit hooks:** Ensure they pass before pushing

### Testing Requirements
1. **Mock AWS API calls:** Never make real AWS calls in tests
2. **Mock file system:** Use unittest.mock for file operations
3. **Test edge cases:** Expired tokens, missing credentials, API errors
4. **Maintain coverage:** Add tests for new features

### Common Pitfalls to Avoid
1. **Don't commit to main:** Always use feature branches
2. **Check dependencies:** Ensure boto3 stubs version compatibility
3. **Pyre vs Mypy:** Both are configured; address issues from both
4. **Global logger:** Initialize `log` before use in all functions
5. **ARN parsing:** Different formats for IAM vs STS identities

### When Making Changes
1. Read existing code patterns before implementing
2. Match existing naming conventions
3. Use NamedTuples for data structures (not classes)
4. Add debug logging for AWS API interactions
5. Handle all AWS ClientError types appropriately
6. Update tests to cover new code paths
7. Run all linters and formatters before committing

### Package Distribution
- Uses Poetry for building and publishing
- Published to PyPI as `aws-account`
- Recommended installation via pipx
- Entry point: `aws-account` command → `aws_account.cli:main`

## Useful Commands Reference

```bash
# Development
poetry install                          # Install dependencies
poetry shell                           # Activate virtual environment
poetry add <package>                   # Add dependency
poetry run aws-account                 # Run the tool

# Testing
poetry run pytest                      # Run tests
poetry run pytest -v                   # Verbose test output
poetry run pytest --cov                # With coverage

# Code Quality
poetry run flake8 aws_account          # Lint code
poetry run yapf -i -r aws_account      # Format code
poetry run isort aws_account           # Sort imports
poetry run mypy aws_account            # Type check
poetry run pyre check                  # Alternative type check

# Pre-commit
pre-commit install                     # Install hooks
pre-commit run --all-files             # Run all hooks

# Building
poetry build                           # Build distribution
poetry publish                         # Publish to PyPI

# Git
git checkout -b feature/name           # Create feature branch
git add .                              # Stage changes
git commit -m "message"                # Commit
git push -u origin feature/name        # Push branch
```

## Configuration Files Quick Reference

| File | Purpose | Key Settings |
|------|---------|--------------|
| `pyproject.toml` | Poetry config, dependencies, scripts | Entry point: `aws_account.cli:main` |
| `.flake8` | Linting rules | Max line length: 120 |
| `.pre-commit-config.yaml` | Git hooks | flake8, yapf, isort, pip-audit |
| `.yamllint.yaml` | YAML linting | Standard rules |
| `.checkov.yaml` | Security scanning | IaC security checks |
| `.bandit` | Python security | Security issue detection |
| `.pyre_configuration` | Type checking | Pyre settings |

## Resources

- **Documentation:** See README.md for user-facing docs
- **Issues:** https://github.com/rollwagen/aws-account/issues
- **Poetry docs:** https://python-poetry.org/docs/
- **Boto3 docs:** https://boto3.amazonaws.com/v1/documentation/api/latest/index.html
- **Click docs:** https://click.palletsprojects.com/

---

**Last Updated:** 2025-11-17
**Claude.md Version:** 1.0
