# AI-assisted development guidelines

## Strict rule: no direct pushes to `main` — ever

> **This is the most important rule.** All changes, without exception, must go through a feature branch and a Pull Request. Direct pushes to `main` are strictly forbidden for everyone, including the AI.

### Enforcement (GitHub repo settings)

Enable branch protection for `main`:

1. **Settings → Branches → Add branch protection rule**
2. Branch name pattern: `main`
3. ✅ `Require a pull request before merging`
4. ✅ `Require status checks to pass before merging` (select `test`, `lint`, `docs`)
5. ✅ `Require branches to be up to date`
6. ✅ `Do not allow bypassing the above settings`
7. ❌ `Allow force pushes` — **must be unchecked**

This prevents both human error and AI from writing directly to `main`.

### Workflow

1. Start from `main` — always branch off the latest `main`:
   ```bash
   git checkout main && git pull origin main
   git checkout -b <type>/<short-description>
   ```
2. Make changes, run tests, commit **on the feature branch only**.
3. Push the feature branch and create a Pull Request:
   ```bash
   git push origin <branch>
   gh pr create --title "<type>: <description>" --body "Closes #<issue>"
   ```
4. Never use `git push origin main` — if it happens, force-push protection on the remote will reject it.

### Branch naming convention

- `feat/<short-description>` — new features
- `fix/<short-description>` — bug fixes
- `docs/<short-description>` — documentation (README, MkDocs, AGENTS.md)
- `refactor/<short-description>` — code refactoring
- `test/<short-description>` — test-only changes
- `chore/<short-description>` — tooling, CI, dependencies

### Auto-merge

- Include `Closes #<issue-number>` in the PR description to automatically close the related issue when the PR is merged (GitHub native feature).
- An automated workflow merges PRs labelled `auto-merge` when all checks pass and a review is approved.
- PRs labelled `hold` will never be merged automatically.
- PRs ready to merge without the `auto-merge` label trigger a notification to the maintainer.

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
