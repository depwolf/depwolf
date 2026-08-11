# DepWolf — Phased Implementation Roadmap

Design-first: each phase is fully tested and merged before the next begins.
Each phase preserves `depwolf scan`/`depwolf sync` compatibility so the tool
stays usable during the migration. Phase zero is the only "big bang" step; the
rest are incremental.

## Phase 0 — Architecture foundation (migration scaffold)
Goal: introduce package layout + DI without changing behavior.
- Restructure to `depwolf/domain`, `depwolf/application`,
  `depwolf/infrastructure`, `depwolf/interfaces` (move existing modules, add
  thin `__init__` re-exports so imports keep working).
- Introduce `IndexStore` port; make current matcher functions accept an
  injected store with a default backed by `DB_PATH`.
- Add `conftest.py` fixtures building an in-memory/temp index; remove the
  `skipif` pattern in `test_scan.py`.
- Add ruff + mypy config, `py.typed`, set `requires-python = ">=3.12"`.
- Outcome: `pytest` runs the full suite with no env vars; same CLI behavior.

## Phase 1 — Single shared version engine + property tests
Goal: fix the demonstrated version-divergence bug (REVIEW A.1.4).
- Create `domain/versions.py`: port `cpe_index._version_key` + `_version_in_range`;
  make it the one implementation.
- Delete `remediation._version_key`; route remediation through the shared engine.
- Add Hypothesis property tests (reflexivity, transitivity, epoch/letter cases,
  NVD real-world examples).
- Outcome: matcher and remediation provably agree.
- Status: **DONE** — `remediation._version_key` deleted, shared engine (incl.
  a fixed Debian-epoch bug found by the property tests) is the only
  implementation; `tests/test_versions_property.py` covers ordering,
  reflexivity/transitivity, epochs, letters, and NVD ranges; `_bump_version`
  now bumps the trailing digit run in place instead of mangling epochs/suffixes;
  Hypothesis added to `dev` extra.

## Phase 1.5 — Full AI remediation narrative
Goal: optional LLM-written remediation beyond the executive summary, still
DB-grounded.
- `_ai_summary` replaced by `_ai_narrative`: one OpenAI chat-completions call
  returns JSON (`executive_summary`, `root_cause`, `step_by_step_fix`,
  `verification`); the model is told the verified facts and forbidden from
  inventing versions/scores; malformed output falls back per-field to the
  deterministic templates.
- `remediation_source` (`ai`/`template`) and `verification` added to output;
  `depwolf scan` entries carry `verification` too.
- Status: **DONE** — see `depwolf/application/remediation.py`; network-free
  tests in `tests/test_remediation.py`.

## Phase 2 — Composable AVIP funnel (ADR-004, ADR-014)
Goal: funnel becomes a Filter chain; no behavior change.
- `domain/funnel.py`: `Filter` protocol + `Funnel` (ordered chain), verdicts
  keep the existing reason strings so output/reports stay compatible.
- Port each `prioritize_cves` branch to a filter
  (invalid_id, not_found, os_mismatch, ignored, not_in_stack, low_risk).
- Add a unit test per filter; keep `prioritize_cves` as a thin facade.
- Outcome: same results, composable and testable; first step toward policy.
- Status: **DONE** — `domain/funnel.py` (`Filter`, `Funnel`, `FilterContext`)
  + `application/filters.py` (6 filters, reasons byte-compatible) +
  `tests/test_funnel.py` (per-filter units + custom-filter composability).
  Reworked on top of the canonical model (Phase 1.6) and repository (Phase 1.7):
  `prioritize_cves` is now a facade over the chain; custom filters plug in.

## Phase 1.6 — Canonical domain model (ADR-017)
Goal: one typed Finding object every layer consumes; no module understands a
raw scanner JSON schema.
- `domain/model.py`: `Dependency`, `CVEReference`, `Finding`, `Asset`,
  `ProductMatch`, `VulnRange` (typed DB row boundary).
- Status: **DONE** — model created; `VulnRange`/`Asset`/`ProductMatch` are the
  typed boundary between the repository and the funnel/matcher today; adapter
  path (ingest.py -> `CVEReference`/`Finding`) lands with Phase 4.
- Status (extension): **DONE** — `CVEReference` gained `to_dict`/`from_dict`,
  `Finding.to_entry_dict()` is the single canonical report-entry serializer
  (kills report key-guessing + CLI meta re-merge), and the full typed set
  (`Enrichment`, `RiskAssessment`, `PolicyVerdict`, `Remediation`) is wired
  through `matcher._build_entry`.

## Phase 1.7 — CVERepository port (replaces leaky IndexStore)
Goal: domain never touches `sqlite3`; repository returns typed objects.
- `domain/ports.py`: `CVERepository` protocol (no connections, no SQL leak).
- `infrastructure/store.py`: `SqliteIndexStore` implements it (`cve`,
  `cves_for_product`, `cve_ids_for_product`, `resolve_products`, `ignored`,
  `all_ignored`, `ignore`, `unignore`); `open()`/`close()` kept only for
  seeding.
- `domain/match.py`: pure fuzzy/OS/asset matching extracted from matcher.
- matcher/remediation/scanner migrated; `prioritize_cves` facade preserved.
- Status: **DONE** — 43 tests pass, ruff + mypy clean, CLI byte-compatible.
- Status (extension): **DONE** — batch methods `resolve_products_many`,
  `cves_for_products`, `cves_for_ids` added to the port and implemented
  single-connection in `SqliteIndexStore` (see Phase 3).

## Phase 3 — Batch index matching (ADR-015)
Goal: kill the double-query + connection-per-call pattern (REVIEW A.1.6).
- `IndexStore.lookup_cves(product, version)` batched for all deps in one pass;
  prepared statements; single connection per scan.
- Remove the `candidates_for_stack` then `prioritize_cves` re-query in
  `scanner.py`/`cli.py`.
- Benchmark on a large repo (e.g. a lockfile-heavy monorepo) — target
  sub-second matching.
- Status: **DONE** — `resolve_products_many` / `cves_for_products` /
  `cves_for_ids` run on one connection (prepared `OR`/`IN`), `_build_plan`
  resolves a whole stack in 2 repository calls, `prioritize_cves(plan=...)`
  accepts a precomputed plan and `match_plan()` is the shared public entry
  point; `scanner.py` and `cli.py` pass the plan in, so a native scan touches
  the DB exactly once. `open_count` is a test seam (`tests/test_batch.py`).

## Phase 4 — Plugin parser architecture (ADR-006/007)
Goal: requirement 4 — independently installable ecosystem/scanner plugins.
- Define `ParserPlugin` protocol + `depwolf.parsers` entry-point group +
  `ParserEngine` (discovery, capability check, per-file isolation).
- Convert existing `scanner.py` parsers into bundled plugins (pip, npm, go,
  maven, gradle, nuget, composer, cargo, ruby, swift) behind the same API;
  leave the `scanner.py` regex dict as the fallback for now.
- Add typed scanner parsers (trivy, grype, snyk, depcheck, semgrep, codeql,
  sarif) with schema validation; keep `ingest` heuristics as last resort.
- Plugin contract tests: a fixture plugin that must load, parse, and fail
  cleanly.
- Status (parsers only): **DONE** — `application/adapters.py` implements typed
  `ScannerAdapter`s (trivy, grype, snyk, dependency-check, semgrep, codeql,
  sarif) emitting canonical `CVEReference` objects with `source`/`confidence`;
  a heuristic adapter (0.3) is the last-resort fallback. Plugin/entry-point
  discovery remains as specified.

## Phase 5 — Config + logging + CLI surface (ADR-010/016)
Goal: requirement 8/9/13 — `depwolf config`, consistent flags, structured logs.
- Config loader (CLI > env > repo `.depwolf.toml` > user config > defaults);
  secrets via env/keyring; `config show` redacts.
- `depwolf config init|get|set|validate|show`, `depwolf version`.
- Uniform `--output`, `--severity`, `--ignore-unfixed`, `--exit-code`,
  `--offline`, `--cache-dir` on `scan`.
- Structured logging (JSON optional, `--debug`, no secrets); replace mixed
  `print()`/`logger` with a single logger in the CLI layer.
- Refactor `_scan` monolith into `ScanProjectUseCase` + `Runner`.

## Phase 6 — Policy engine + suppressions/VEX (ADR-009)
Goal: requirement 7 — org rules, ignore lists, suppressions, custom advisories,
internal CVEs, VEX.
- YAML policy DSL: severity gates, threshold, require-fixed, blocklist,
  environment rules; evaluated in domain.
- `depwolf policy validate|export|import|test`.
- Suppressions table (expiry-aware), `depwolf ignore|unignore|suppress`.
- VEX import (CSAF) + export; custom advisories + internal CVEs feed the funnel
  as extra filters.
- Outcome: exit code and severity filtering driven by policy, not hardcoded.
- Status (policy core): **DONE** — `domain/policy.py` (`Policy`, `load_policy`,
  `dump_policy`, `apply_policy`) evaluates severity gates, `min_risk`,
  `require_fixed`, and `blocklist` to a `PolicyVerdict` (allow/warn/deny +
  patch priority/SLA). Risk, priority, and policy are separated:
  `domain/risk.py` returns a priority-free `RiskResult`, `domain/priority.py`
  computes patch priority/SLA, and `matcher._build_entry` applies the policy
  per finding. `depwolf policy` subcommands, suppressions, and VEX remain as
  specified.

## Phase 7 — SBOM module (ADR-013)
Goal: requirement 7 (SBOM enrichment, license compliance) + CycloneDX/SPDX
formats in requirement 5.
- `depwolf sbom generate|enrich|export` from parsed deps (shared with scan).
- CycloneDX 1.5 + SPDX 2.3 writers via the `depwolf.reporters` group.
- License metadata from index/manifests; dependency health (age, abandoned,
  outdated) as enrichment fields.
- Wire `--format cyclonedx|spdx` on `scan`.

## Phase 8 — HTML + PDF reports
Goal: requirement 5 — dashboards and executive PDFs.
- HTML dashboard (self-contained, dark-mode, risk treemap, KEV banner).
- Executive PDF (HTML->PDF pipeline or reportlab) with severity summary,
  top findings, SLA table, remediation summary.
- Golden-file tests for all formats.

## Phase 9 — Signed incremental index + sync engine (ADR-002)
Goal: requirements 2/3 — signed updates, incremental, versioning, rollback,
checksum, CDN, offline DB.
- Bundle format: `latest.json` (version, sha256, ed25519 sig, chunk urls) +
  chunked deltas; build from NVD/EPSS/KEV in the index-builder job.
- `IndexSync` port: http adapter with parallel resumable downloads + cache dir;
  verify chunk/whole hashes + signature; atomic swap; keep previous; rollback.
- `depwolf sync --check --channel stable --rollback`, `depwolf update`,
  `depwolf db build|verify|info|repair`.
- Signing: build-time Ed25519 key; public key pinned in config; TOFU with
  recorded fingerprint.
- Keep `AVIP_DB_URL` full-blob download as a fallback path.
- Status (checksum + Ed25519 verification, no incremental deltas): **DONE** —
  `infrastructure/index_sync.py` writes a `manifest.json` (sha256 per file +
  optional Ed25519 signature) after every `build_index`; `download_index`
  verifies the `<url>.sha256` sidecar then the local manifest; `verify_index`
  falls back to a bare table check for legacy DBs; `depwolf sync --check` and
  `depwolf db` surface verification. Incremental chunked deltas, rollback, and
  key TOFU remain as specified.

## Phase 10 — Normalized schema + migration (ADR-001)
Goal: the 10x compaction + provenance (enables Phase 9 rollback properly).
- New tables `cves` / `products` / `vuln_ranges` / `index_meta`; builders emit
  normalized bundles; `depwolf db build` migrates the old index.
- Index queries rewritten against the new schema (IndexStore is the seam).
- Outcome: smaller bundles, incremental sync, rollback metadata.

## Phase 11 — Performance & concurrency
Goal: requirement 8.
- Per-manifest worker pool (ThreadPoolExecutor); async downloads in sync engine.
- Disk cache for parsed manifests + scan results (incremental scans);
  `.depwolfignore` support.
- Memory optimization: stream large reports, cap context depth.
- Benchmarks in CI (scan time on a large fixture repo).

## Phase 12 — Cloud backend (FastAPI + Postgres + Redis + S3 + CDN)
Goal: requirement 2 — scalable backend for org features.
- FastAPI service with OAuth2 client-credentials + org-scoped API keys.
- Postgres: orgs, findings, policy, suppressions, VEX, advisories.
- Redis: job queue, rate limit, cache. Object storage: reports/SBOMs/index
  bundles. CDN for index chunks.
- `POST /api/v1/scan` async job flow; webhook notifications on gate.
- CLI `--remote`/`--org` to submit scans to the org service (opt-in).

## Phase 13 — CI/CD templates + release engineering
Goal: requirements 6/10/13.
- GitHub Actions, Jenkins, GitLab CI, Azure DevOps, Bitbucket Pipelines
  templates (shared test fixtures in `ci/`).
- Release pipeline: lint -> test matrix (py3.12/3.13 x linux/win/mac) -> build
  sdist/wheel/docker/PyInstaller -> publish PyPI + GitHub Release + registry;
  signed releases + SBOM of depwolf itself.
- Index-builder cron job (NVD/EPSS/KEV -> sign -> publish -> bump manifest).

## Phase 14 — Hardening, telemetry, docs
Goal: requirements 9/12/15 — secure by default, opt-in telemetry, docs.
- Security review pass (least privilege docs, secret redaction audit,
  parser sandbox verification, AI rate limiting).
- Opt-in telemetry (consent file; sends version/scan counts only; never source).
- Docs: README, INSTALL, ARCHITECTURE, API, CI/CD examples, CONTRIBUTING,
  RELEASE; architecture diagrams; ADRs.
- Contribution guide with plugin-author tutorial and contract tests.

## Suggested priority order for early wins
1. Phase 0 + Phase 1 (foundation + version bug) — unlocks everything.
2. Phase 2 + Phase 3 (funnel composition + perf) — core quality.
3. Phase 5 + Phase 6 (config + policy) — enterprise differentiation.
4. Phase 9 (signed sync) — the cloud story that makes it "just works".
