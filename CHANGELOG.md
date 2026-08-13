# Changelog

All notable changes to depwolf are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.6] - 2026-08-13

### Added
- Standalone `depwolf remediate <CVE>` now infers the ecosystem of well-known
  library products (xstream, log4j, jackson-databind, jquery, axios, flask,
  django, rails, ...) so it emits real Maven/npm/pip/Bundler commands instead of
  a generic "No OS package maps" advisory. Versions and coordinates stay
  DB-grounded/curated — nothing is AI-invented, and missing version context is
  reported honestly (`installed_version`/`applicable` remain null).

## [0.1.5] - 2026-08-13

### Added
- Product-match confidence on every finding (`exact` / `alias` / `canonical` /
  `fuzzy` / `heuristic`); `exact`/`alias`/`canonical` are HIGH confidence.
- Dependency identity in manifest parsing: Maven `groupId`/`artifactId`, npm
  scope, Go module path, plus direct/transitive and dependency-path detection
  for `package-lock.json` (v1) and `Cargo.lock`.
- `depwolf verify <CVE...> --version <v>` → `FIXED` / `STILL VULNERABLE` /
  `UNABLE TO VERIFY` (UNABLE is never treated as FIXED).
- Ecosystem-aware remediation (Maven, npm, pip, Go, Cargo, Bundler, Composer):
  exact patch commands, a concrete `file_change` before/after, `minimum_safe_version`,
  transitive-dependency explanation, and a major-version `compatibility_warning`.
  Template verification steps are always present (never null).
- Reporting semantics: findings are now labelled `actionable` / `not_applicable`
  / `risk_suppressed` with an `overall reduction` rate; legacy `fp-rate` only
  counts proven non-applicable CVEs.

### Changed
- Filter explanations distinguish "product not in project" from "installed
  version outside the vulnerable range (with the exact range)".
- `low_risk` detail now includes the exact risk score and the 35 threshold.
- `render_table` adds `Version` and `Confidence` columns.
- AI remediation prompt rewritten to answer 9 concrete remediation questions
  over DB-verified facts only; the model never supplies versions/CVSS/coordinates.

## [0.1.4] - 2026-08-13

### Fixed
- Empty or truncated local index is auto-detected and re-downloaded: a scan now
  checks row count (`SELECT COUNT(*)`) and replaces a 0-row DB instead of
  silently reporting every CVE as `not_found`. Clear error if no network.
- Table/JSON findings now report only the stack assets that actually match a
  CVE instead of the whole merged stack (previously the `Pkg` column showed the
  same first asset on every row).
- Directory scans skip `site-packages`, `dist-info`, and `egg-info` directories,
  removing venv noise (`entry_points.txt`, `requires.txt`, schema files) from
  results.

## [0.1.3] - 2026-08-12

### Fixed
- Directory scans no longer crash on one malformed JSON report: unparseable
  files are skipped with a `[warn]` instead of raising `SystemExit`.
- UTF-8 BOM in scanner JSON is stripped before parsing, so BOM-prefixed
  trivy/grype output is parsed with the structured adapter (not the low-
  confidence text heuristic).

## [0.1.2] - 2026-08-12

### Added
- Zero-config first run: `pip install depwolf` → `depwolf scan` (or `depwolf
  sync`) downloads the prebuilt `cpe_index.db` from the default release CDN when
  none exists locally. `AVIP_DB_URL`/`AVIP_DB_PATH` remain as overrides.
- `depwolf sync --full` forces a full rebuild from NVD/EPSS/KEV (default is now
  a download).

### Changed
- `download_index` falls back to `DEFAULT_DB_URL` (GitHub Release asset) when
  neither an argument nor `AVIP_DB_URL` is set.

## [0.1.1] - 2026-08-12

### Added
- Index build automation (`.github/workflows/build-index.yml`): `workflow_dispatch`
  job builds the full signed `cpe_index.db` on a GitHub runner and uploads it as
  release assets (`cpe_index.db`, `cpe_index.db.sha256`,
  `cpe_index.db.manifest.json`) for the `index-v1` release.

### Changed
- `download_index` now pulls the signed `manifest.json` sidecar
  (`<url>.manifest.json`) so fresh installs verify the Ed25519 signature when
  `AVIP_INDEX_PUBKEY` is configured.
- `verify_index`: a signed manifest passes when no pubkey is configured (checksum
  remains the hard gate); an empty `AVIP_SIGNING_KEY_PATH`/
  `AVIP_SIGNING_PUBKEY_PATH` env var explicitly disables the default key paths.

## [Unreleased]

### Added
- OSS/startup hardening: `LICENSE` (Apache-2.0), `SECURITY.md`, `CONTRIBUTING.md`,
  `CHANGELOG.md`, `.editorconfig`, `.pre-commit-config.yaml`, `dependabot.yml`.
- CI gates (`.github/workflows/ci.yml`): ruff, ruff-format, mypy, pytest with
  coverage, wheel/sdist build + fresh-venv smoke test, across Python 3.12/3.13
  and Ubuntu/Windows. Coverage is a regression floor for now; the push to 80%
  lands with the post-FP hardening pass.
- Release automation (`.github/workflows/release.yml`): tag `v*` -> version
  match check -> build -> sigstore attestation -> PyPI trusted publish ->
  GitHub Release.
- `depwolf --version` subcommand-agnostic version flag.
- PyPI metadata: classifiers, project URLs, single-source `__version__`,
  coverage configuration, `pytest-cov` in dev extras.

### Changed
- **P0-1 canonical model** (`domain/model.py`): full typed set —
  `Dependency`, `CVEReference` (with `to_dict`/`from_dict`), `Enrichment`,
  `RiskAssessment`, `PolicyVerdict`, `Remediation`, `Finding` (with
  `to_entry_dict()` as the single canonical report-entry serializer). Kills the
  CLI meta re-merge and report key-guessing.
- **P2-2 risk/priority/policy separation**: `RiskResult` is priority-free;
  patch priority/SLA moved to `domain/priority.py`; new `domain/policy.py`
  YAML policy engine (`load_policy`/`dump_policy`/`apply_policy`) emitting
  allow/warn/deny verdicts. `PyYAML` added to runtime deps.
- **P1-4 batch matching**: `CVERepository` port gains `resolve_products_many`,
  `cves_for_products`, `cves_for_ids`; `SqliteIndexStore` implements them on a
  single connection. `matcher._build_plan` resolves a whole stack in 2 repo
  calls; `match_plan()` is the shared entry point and `prioritize_cves` accepts
  a precomputed `plan`. Native scans touch the DB exactly once.
- **P1-5 typed adapters**: new `application/adapters.py` — `ScannerAdapter`
  protocol + trivy/grype/snyk/dependency-check/semgrep/codeql/sarif adapters
  emitting `CVEReference` with `source`/`confidence`; heuristic (0.3) last-resort
  fallback; `ingest.py` rewired, public API shape preserved.
- **P2-1 signed/checksummed sync**: `infrastructure/index_sync.py` writes a
  `manifest.json` (sha256 per file + optional Ed25519 signature) after every
  build; `download_index` verifies the `<url>.sha256` sidecar then the local
  manifest; `verify_index` falls back to a table check for legacy DBs.
  `cryptography` added to `dev`/`sync` extras.
- **CLI**: `scan` passes typed refs (no meta re-merge), new `db` command
  (path/verification/stats), `sync --check` verifies index integrity.
- `report.py` reads canonical keys (`affected_assets`, `patch_priority`).

## [0.1.0] - 2026-01-01

### Added
- Initial release: CVE extraction from any scanner output, AVIP FP funnel,
  DB-grounded remediation, `sync`/`ignore`/`export` commands, SARIF/JSON/table
  output, `depwolf scan` gate with `--threshold`.

[0.1.0]: https://github.com/depwolf/depwolf/releases/tag/v0.1.0
[0.1.1]: https://github.com/depwolf/depwolf/releases/tag/v0.1.1
[0.1.2]: https://github.com/depwolf/depwolf/releases/tag/v0.1.2
[0.1.3]: https://github.com/depwolf/depwolf/releases/tag/v0.1.3
