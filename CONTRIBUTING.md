# Contributing

## Development Setup
1. Fork and clone
2. Create venv: `python -m venv .venv && source .venv/bin/activate` (or PowerShell equivalent)
3. Install: `pip install -e .[dev]`
4. Run tests: `pytest -q`
5. Lint/format: `ruff check . && ruff format .`

## Conventional Commits
Use format: `type(scope?): subject`
Types: feat, fix, chore, docs, refactor, perf, test, build, ci, security.

## Pull Requests
- Keep PRs focused
- Add/Update tests for changed logic
- Update CHANGELOG.md (Unreleased section)

## Release Process
Automated via Git tag push. Use `python scripts/bump_version.py <new_version>` then tag:
```
./scripts/bump_version.py 1.1.0
git add pyproject.toml CHANGELOG.md
git commit -m "chore(release): 1.1.0"
git tag v1.1.0
git push origin main --tags
```

## Code Style
- 100 char lines
- Prefer explicit over implicit
- Avoid broad bare exceptions (only where annotated pragma: no cover)

## Security
Report privately (see SECURITY.md). Do not open public issues for vulnerabilities.
