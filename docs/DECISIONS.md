# DepWolf — Decision Records (ADRs)

Format per record: Decision / Alternatives / Pros / Cons / Why chosen.

## ADR-001 Normalize the index schema (cves / products / vuln_ranges)
- **Decision**: Replace the single `cpe_index` table with normalized
  `cves`, `products`, `vuln_ranges`, `index_meta`.
- **Alternatives**: (a) keep denormalized, (b) columnar store, (c) Parquet.
- **Pros**: ~10x compaction; provenance/versioning/rollback become DB
  properties; incremental sync is tractable; SQLite still works offline.
- **Cons**: joins cost a bit; one-time migration + re-index.
- **Why**: the current 1.5 GB of duplicated text is the root cause of slow
  syncs, no-rollback, and opaque provenance.

## ADR-002 Introduce a signed, versioned, incrementally updatable index bundle
- **Decision**: SyncEngine downloads a small signed `latest.json` manifest,
  then deltas/chunks, verifies SHA256 + Ed25519, swaps atomically, keeps
  previous version, rolls back on failure.
- **Alternatives**: full-blob download, rsync-style deltas, live SQLite
  federation.
- **Pros**: trustworthy supply chain (a security tool must not trust a plain
  URL), fast updates, offline bundles, CDN-friendly.
- **Cons**: needs a signing key lifecycle and a build pipeline.
- **Why**: an unauthenticated 1.5 GB blob is an integrity hole; incremental is
  required for "sync in seconds".

## ADR-003 `IndexStore` port + dependency injection (no import-time DB_PATH)
- **Decision**: All DB access goes through an injected `IndexStore`; module-level
  `DB_PATH`/env-at-import removed.
- **Alternatives**: keep global, use a settings object, monkeypatch in tests.
- **Pros**: multi-DB in one process, in-memory test fixtures, no
  skip-if-no-env test dance, clean connection lifecycle.
- **Cons**: mild boilerplate (resolved by a small container/factory).
- **Why**: the env-before-import pattern is why the core tests silently skip.

## ADR-004 Make the funnel a composable Filter chain (domain)
- **Decision**: `Filter` protocol + ordered chain; each filter returns a
  verdict; policy can reorder/inject filters.
- **Alternatives**: keep the monolith, state machine, rules engine (OPA).
- **Pros**: every FP class is independently testable; orgs can inject
  suppression/VEX/license filters; OPA can sit behind the same port later.
- **Cons**: slightly more code up front.
- **Why**: the funnel is the product's value; a monolith that must be edited
  for every new rule will not scale.

## ADR-005 Single shared version engine in `domain/versions.py`
- **Decision**: One version tokenizer + range evaluator used by matching, risk,
  and remediation. Delete `remediation._version_key`.
- **Alternatives**: keep two, standardize on PEP 440, delegate to `packaging`.
- **Pros**: eliminates the demonstrated divergence bug; one property-tested
  engine; no runtime dep (keep it stdlib, `packaging` optional).
- **Cons**: none meaningful.
- **Why**: two divergent version models already disagree on real CVEs.

## ADR-006 Plugin architecture via entry-point groups, not a hardcoded dict
- **Decision**: `depwolf.parsers` and `depwolf.reporters` entry-point groups;
  `importlib.metadata` discovery; per-plugin `schema_version`.
- **Alternatives**: hardcoded registry, vendored plugin dir, dynamic import of
  installed modules.
- **Pros**: independently installable (pip/npm/maven/gradle/nuget/composer/
  cargo/go/ruby/swift as separate wheels); external contributors; versioned
  API; broken plugin is contained.
- **Cons**: entry-point discovery overhead (trivial), plugin API stability work.
- **Why**: requirement 4 (independently installable plugins) and
  maintainability both point here.

## ADR-007 Typed per-scanner parsers replace the universal regex
- **Decision**: Keep `ingest` heuristics as a last-resort fallback but add
  typed parsers for trivy/grype/snyk/depcheck/semgrep/codeql/sarif via the
  parser plugin API.
- **Alternatives**: regex-only, auto schema sniff only.
- **Pros**: accurate pkg/version/severity context (FP reduction depends on it),
  schema-validated, faster.
- **Cons**: more parsers to maintain (offset by plugin contributions).
- **Why**: sibling-key heuristics mis-associate context and degrade the funnel.

## ADR-008 Offline-first core, cloud as optional org layer
- **Decision**: Local scan never requires network. Cloud (FastAPI + Postgres +
  Redis + object storage + CDN) is optional and additive.
- **Alternatives**: cloud-required thin client, fully local only.
- **Pros**: works in air-gapped enterprises and every CI; cloud adds org
  features without being a SPOF.
- **Cons**: two codebases to maintain (CLI + API share application/domain).
- **Why**: air-gapped and "use immediately in any pipeline" requirements.

## ADR-009 Policy engine as a domain DSL with an optional OPA backend
- **Decision**: YAML policy DSL evaluated in-domain (zero-dep), plus an
  `OPA` port for orgs that want Rego.
- **Alternatives**: Rego-only, JSON-only rules, hardcoded thresholds.
- **Pros**: no runtime dep for the common case; orgs can express severity
  gates, suppressions, VEX, custom advisories, license rules.
- **Cons**: we own a small DSL.
- **Why**: requirement 7 features must be data-driven, not code-edited.

## ADR-010 CLI built on argparse but organized as a command router
- **Decision**: Keep argparse (zero-dep) but add subparser-per-command modules,
  a single `Runner`, and uniform `--output/--format/--severity/--exit-code/
  --offline/--cache-dir`.
- **Alternatives**: click/typer (adds deps), hand-rolled dispatch.
- **Pros**: zero-dep property preserved; per-command testability; consistent
  flags.
- **Cons**: argparse verbosity (managed by the router pattern).
- **Why**: distribution + supply-chain goals favor zero runtime deps.

## ADR-011 Property-test the version engine; fixture-built index for tests
- **Decision**: Hypothesis property tests for `versions.py`; conftest fixtures
  build a small index in-memory so DB tests never skip.
- **Alternatives**: keep skip-if-no-env, golden-file-only.
- **Pros**: the most bug-prone code gets real coverage; CI runs everything.
- **Cons**: Hypothesis is a dev dep only.
- **Why**: review finding A.1.13.

## ADR-012 Risk weights come from policy, defaults match current model
- **Decision**: `risk.py` keeps the proven CVSS/EPSS/KEV model as defaults;
  weights/scoring fn become policy-configurable.
- **Alternatives**: fixed forever, ML scoring.
- **Pros**: backward-compatible output; orgs can tune without forking.
- **Cons**: weight tuning needs validation tooling.
- **Why**: enterprises demand customizable scoring without losing the
  deterministic core.

## ADR-013 SBOM + VEX as first-class modules (CycloneDX/SPDX)
- **Decision**: `depwolf sbom` generates CycloneDX/SPDX from parsed deps;
  VEX import/export overlays known/not-affected on findings.
- **Alternatives**: outsource to syft/cyclonedx-python (deps).
- **Pros**: self-contained, offline, feeds policy/suppression.
- **Cons**: SPDX/CycloneDX writers are a chunk of work (phase-gated).
- **Why**: requirement 7 (SBOM enrichment, VEX, license compliance).

## ADR-014 Distribution: pip + Docker + per-OS binaries via CI matrix
- **Decision**: sdist/wheel on PyPI, multi-stage Docker image, PyInstaller
  binaries for linux/windows/macos built in CI.
- **Alternatives**: only pip, only Docker, uv-managed tool.
- **Pros**: matches `pip install depwolf` + `docker run depwolf` goal; binaries
  for air-gapped Windows/macOS.
- **Cons**: PyInstaller build complexity (contained to CI).
- **Why**: requirement 10.

## ADR-015 Batch index lookups on a single reused connection
- **Decision**: resolve all (product, version) pairs against the index in one
  pass with prepared statements; drop the double-query (candidates then
  prioritize) pattern.
- **Alternatives**: current per-asset LIKE cascade + per-call connections.
- **Pros**: removes the 2x work and dozens of connections; faster on large repos.
- **Cons**: none.
- **Why**: review finding A.1.6.

## ADR-016 Configuration precedence + secrets hygiene
- **Decision**: CLI > env > repo config > user config > defaults; secrets only
  from env/keyring; `config show` redacts.
- **Alternatives**: single config file, everything env.
- **Pros**: per-project policy, org-overridable, safe secret handling.
- **Cons**: none meaningful.
- **Why**: requirement 9 (secure configuration, encrypted keys).

## ADR-017 Canonical Finding model (model-first, not folder-first)
- **Decision**: `domain/model.py` defines one typed Finding object
  (`Dependency`, `CVEReference`, `Finding`, plus the typed DB boundary types
  `Asset`, `ProductMatch`, `VulnRange`). Every adapter produces a Finding;
  every downstream stage (funnel, risk, policy, remediation, reporting)
  consumes one. No module other than the owning adapter understands a raw
  scanner JSON schema.
- **Alternatives**: keep untyped dicts flowing everywhere; a model per layer;
  no model (folders-first).
- **Pros**: kills the CLI `_scan` meta re-merge, the reporter key-guessing
  (`asset or pkg`), and the remediation DB re-query; "same finding from two
  scanners" becomes computable; reachability/license/policy attach to a typed
  object.
- **Cons**: a migration cost that must be paid across matcher/ingest/report.
- **Why**: the current codebase is a well-executed MVP whose remaining coupling
  is all caused by shapeless dicts. Model-first is the keystone the rest of the
  roadmap hangs on.

## ADR-018 `CVERepository` port replaces the leaky `IndexStore`
- **Decision**: `domain/ports.py` exposes `CVERepository` returning typed
  objects (`VulnRange`, `ProductMatch`, `set[str]`); no `Connection`, no SQL,
  no `row_factory` crosses the boundary. `infrastructure/store.py`
  `SqliteIndexStore` implements it; `open()`/`close()` remain only as seeding
  helpers.
- **Alternatives**: keep exposing `sqlite3.Connection` from the port
  (type-annotated leak), repository-per-entity (overkill now).
- **Pros**: domain is storage-agnostic (DuckDB/Postgres swap without touching
  domain); product resolution + fuzzy matching live in pure `domain/match.py`;
  prepared-statement batching (ADR-015) can be added behind the same seam.
- **Cons**: none meaningful.
- **Why**: a port that returns the concrete storage API is not a port; it is
  why `matcher.py`/`remediation.py` could not be tested without a real DB.
