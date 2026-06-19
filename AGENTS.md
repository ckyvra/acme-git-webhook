# AI-assisted development guidelines

## Branch workflow

- **Never commit directly to `main`** — all work must be done on a dedicated feature branch.
- Feature branches should follow the naming convention: `feat/<short-description>`, `fix/<short-description>`, `docs/<short-description>`.
- Create a Pull Request from the feature branch to `main` for every change.

## Before creating a PR

1. Run the full test suite:
   ```bash
   make test
   ```
   or directly with the local venv:
   ```bash
   .venv/bin/python -m pytest -v
   ```
2. Run linting:
   ```bash
   make lint
   ```
3. Verify all 260+ tests pass and there are no new warnings.
4. Update documentation to reflect the changes:
   - **README.md** — update usage examples, config reference, API endpoints.
   - **`docs/` (MkDocs)** — keep the English (`en/`) and French (`fr/`) documentation in sync with any new features, config fields, or behavioural changes.
   - **Code comments and docstrings** — ensure public API docstrings are accurate, especially for new or modified endpoints.

## Code conventions

- Follow the existing code style (type hints, docstrings, Pydantic models for configs).
- All public methods must have type annotations.
- Private methods should be prefixed with `_`.
- Keep backward compatibility — new config fields must be optional with sensible defaults.

## Commit messages

Use conventional commits:
```
<type>: <short description>

<optional body>
```

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`.

## Testing

- Tests live in `tests/`, one file per module (`test_<module>.py`).
- New features must include tests for:
  - Valid configuration (defaults and custom values)
  - Invalid configuration (validation errors)
  - Edge cases (None, empty, missing)
  - Integration with existing components when applicable
- Use `unittest.mock.MagicMock` and `pytest` fixtures.

## Security

- Never log secrets, private keys, tokens, or passwords.
- Use `secrets.compare_digest()` for token comparison.
- Sensitive values must be loaded from files at runtime, never from config YAML.
