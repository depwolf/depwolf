# Contributing

Thanks for contributing to depwolf. This is the same standard we expect of a
startup production codebase: small, reviewed, tested changes.

## Code of conduct

Be professional and constructive. Harassment of any kind is not tolerated.
Report issues to `security@depwolf.dev` or the maintainers.

## Development setup

Requires Python >= 3.12.

```bash
python -m venv .venv
.venv/Scripts/activate        # Windows  |  source .venv/bin/activate (Linux/macOS)
python -m pip install -e ".[dev]"
pre-commit install            # optional but recommended
```

## Quality gates

Every change must pass, locally and in CI:

```bash
ruff check depwolf tests      # lint
ruff format --check depwolf tests   # formatting
mypy depwolf                  # static types
python -m pytest tests/ -q --cov=depwolf   # tests; coverage >= 80%
```

Run `ruff format depwolf tests` to auto-format.

## Project layout

```
depwolf/
  domain/           pure logic: versions, matching, funnel, model, ports
  application/      use-cases: matcher facade, filters, remediation, ingest, risk
  infrastructure/   sqlite index store, DB seeding
  interfaces/       CLI, report serialization
tests/              pytest suite (fixtures in conftest.py)
```

## Design principles

- **Deterministic by default.** Matching, risk, and version decisions come
  from `cpe_index.db`; AI (optional) writes narratives only.
- **Typed boundaries.** Database access crosses the `CVERepository` port
  (`depwolf/domain/ports.py`) — no SQL/sqlite types in application code.
- **Pure core, thin shell.** Put logic in `domain`, use-cases in
  `application`, and I/O in `infrastructure`/`interfaces`.
- No new runtime dependencies without discussion; the package is stdlib-only.

## Testing

- Add or update tests for every behavior change.
- `tests/conftest.py` provides `index_store`/`memory_index_store` fixtures and
  the `LOG4J_ROWS` fixture data.
- New public behavior needs a parity test proving output stays stable.

## Commits & PRs

- Concise, imperative commit messages; reference the issue where one exists.
- One logical change per PR; include a changelog entry under
  `## [Unreleased]` in `CHANGELOG.md`.
- CI must be green before merge.

## Release process

Maintainers only. Tag `v<version>` matching `depwolf.__version__`; the
Release workflow builds, attests, publishes to PyPI, and opens a GitHub
Release.
