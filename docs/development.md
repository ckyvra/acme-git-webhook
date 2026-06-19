# Development

## Prerequisites

- Python 3.12+
- A Git repository with Bind zone files (for testing)
- (Optional) HashiCorp Vault, F5 Big-IP, etc. for integration testing

## Local setup

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r dev-requirements.txt
```

## Configuration for development

Create `config.yaml`:

```yaml
auth:
  api_keys:
    - "sk-dev-key"

webhook:
  bind: "0.0.0.0:8000"

repo:
  url: "git@github.com:org/dns-zones.git"
  branch: "main"
  zone_path: "zones"

vault:
  skip: true   # Disable Vault for local dev

dns:
  wait_for_propagation: false
```

Start the server:

```bash
uvicorn app.main:app --reload --port 8000
```

## Running tests

The test suite uses `pytest` with fixtures from `tests/conftest.py`.

```bash
# Full test suite
make test

# Or directly
.venv/bin/python -m pytest -v

# Run a specific test module
.venv/bin/python -m pytest tests/test_config.py -v

# Run with coverage
.venv/bin/python -m pytest --cov=app -v

# Integration tests (Docker + network required)
make test-integration

# Or directly
.venv/bin/python -m pytest --run-integration -v
```

## Linting

```bash
make lint
```

Runs `py_compile` over all application and test source files to verify syntax.

## Development workflow

```make
make check             # lint + test
make test              # run unit tests only
make test-integration  # run all tests including integration
make lint              # syntax check only
make clean             # remove venv and __pycache__
```

## Writing tests

Tests live in `tests/`, one file per module (`test_<module>.py`).

- Use `unittest.mock.MagicMock` for mocking external services (Vault, Git, DNS, F5, etc.)
- Use `pytest` fixtures for shared setup
- New features should include tests for:
  - Valid configuration (defaults and custom values)
  - Invalid configuration (validation errors)
  - Edge cases (`None`, empty, missing)
  - Integration with existing components

See `tests/conftest.py` for shared fixtures and helpers.

## Project structure

```
app/
├── main.py              # FastAPI app, routes, lifespan
├── config.py            # Pydantic models for config.yaml
├── models.py            # Request/response Pydantic models
├── auth.py              # Bearer token authentication
├── git_handler.py       # Git clone/pull/commit/push
├── zone_handler.py      # Bind zone file manipulation (dnspython)
├── vault_handler.py     # HashiCorp Vault integration
├── dns_probe.py         # DNS propagation checker
├── cert_monitor.py      # Certificate expiration monitor
└── targets/
    ├── base.py          # DeployTarget ABC
    ├── manager.py       # DeployManager orchestrator
    ├── f5.py            # F5 Big-IP target
    ├── ivanti.py        # Ivanti VPN target
    ├── exchange.py      # Exchange SMTP target
    └── _crypto.py       # PEM-to-PFX conversion

tests/
├── conftest.py          # Shared fixtures (+ --run-integration option)
├── test_config.py
├── test_main.py
├── test_zone_handler.py
├── test_git_handler.py
├── test_vault_handler.py
├── test_dns_probe.py
├── test_cert_monitor.py
├── test_integration.py  # DNS + Vault integration tests (--run-integration)
├── test_targets_f5.py
├── test_targets_ivanti.py
├── test_targets_exchange.py
├── test_targets_crypto.py
└── test_targets_manager.py
```

## Contributing

1. Create a feature branch: `feat/<short-description>` or `fix/<short-description>`
2. Make your changes following existing code conventions (type hints, docstrings, Pydantic models)
3. Add or update tests
4. Run `make check` — all tests must pass with no warnings
5. Update documentation (README, `docs/en/`, `docs/fr/`) to reflect changes
6. Open a Pull Request to `main`

### Commit messages

Use conventional commits:

```
feat: add support for AcmeCorp target provider

fix: handle empty zone file during cleanup

docs: update API reference with new endpoint
```
