# DepWolf — Critical Architecture Review

Status: DRAFT v1 (design only, no code)
Related: `docs/TARGET.md` (target architecture), `docs/DECISIONS.md` (ADRs), `docs/ROADMAP.md` (phasing)

## A.0 Method

I read every module: `cli.py`, `ingest.py`, `matcher.py`, `scanner.py`,
`cpe_index.py`, `risk.py`, `remediation.py`, `report.py`, `__init__.py`,
`pyproject.toml`, `tests/`, `.github/workflows/sca.yml`. All findings are
grounded in those files with line references.

## A.1 Systemic issues (highest impact first)

### A.1.1 The CVE index is a single denormalized table with no integrity model
`cpe_index.py:70-86` creates one table where every (cve, product, version-range)
row repeats `description`, `cvss_score`, `epss_score`, `kev`, `published_date`.
There is **no PRIMARY KEY, no UNIQUE constraint, no foreign keys, no data
provenance**.

Problems at scale:
- The ~1.5 GB DB is mostly duplicated text; every row for a CVE carries the
  same description and scores.
- Nothing records source (NVD vs EPSS vs KEV) or time, so incremental syncs and
  rollback cannot be reasoned about.
- `meta` only holds `last_mod`; no schema version, no index signature, no
  checksum, no previous-version pointer.

**Better**: normalized `cves` (one row per CVE) + `products` (vendor/product)
+ `vuln_ranges` (range rows referencing cve_id + product_id). ~10x compaction
and makes versioning/rollback a database property. See `docs/TARGET.md` §B.5.

### A.1.2 Module-level `DB_PATH` constant = import-time singleton
`cpe_index.py:6-9` resolves `DB_PATH` from `AVIP_DB_PATH` **at import time**;
`matcher.py:3`, `remediation.py:16`, `cli.py:28` all import that constant.
- Two scans cannot use different databases in one process.
- Tests must set the env var *before* any import, hence
  `tests/test_scan.py:8-9` `pytest.mark.skipif(not DB)` — the **core logic
  silently skips in CI** without a manual DB.
- No dependency injection, no context manager, no connection lifecycle.

**Better**: an `IndexStore` port injected into use cases; test fixtures build an
in-memory/temp DB without env-var gymnastics (ADR-003).

### A.1.3 Flat one-file-per-concern is not a layered architecture
The 8 modules cross-import freely (`cli` imports matcher/remediation/report/
cpe_index/ingest; `matcher` imports cpe_index/risk; `remediation` imports
cpe_index/risk). There is no domain/application/infrastructure separation.
Consequence: `cli.py` orchestrates parsing, DB checks, native scanning, report
merging, remediation, output, and gate exit codes in one `_scan()` (~60 mixed
lines, `cli.py:129-176`). None of that is unit-testable without driving the
whole binary.

### A.1.4 Duplicated and divergent version logic (correctness bug)
- `cpe_index.py:109-130` `_version_key` is a sophisticated tokenizer (epochs,
  letters).
- `remediation.py:48-49` defines a **second** `_version_key` =
  `tuple(int(x) for x in re.findall(r"\d+"))` which **discards letters and
  epochs**. For `1.0.1e` vs `1.0.1g` the matcher sorts them, remediation treats
  them equal. Two engines can disagree on the same CVE — this ships wrong
  "fixed version" advice.
- Three separate normalizers: `cpe_index._normalize` (93), `matcher._compact`
  (209), `ingest._norm_key` (27).

### A.1.5 The funnel is a monolithic if-chain, not a pipeline
`matcher.py:259-372` `prioritize_cves` is ~110 lines of sequential if/elif
branching with early `continue`s and ad hoc string "reasons". Adding one filter
(reachability, license policy, suppression) means editing the monolith. The
funnel is the core product value and the least composable part.

### A.1.6 Matching is O(prefixes x products) per asset, with new DB handles
`matcher.py:69-100` `_find_cpe_products` loops shrinking prefixes and issues a
`LIKE` per prefix. `match_stack` / `candidates_for_stack` / `prioritize_cves`
each open their **own** connection (`matcher.py:131,151,263`). `scanner.py`
resolves candidates via `candidates_for_stack`, then the CLI calls
`prioritize_cves` which re-queries the same products — the same data fetched
twice, sequentially. No prepared statements, batching, or concurrency.

### A.1.7 Manifest parsing is a hardcoded regex dict with no plugin contract
`scanner.py:213-227` maps filenames to functions. TOML is parsed with regex
(`_parse_pyproject`, `_parse_yarn_lock`), XML with regex (`_parse_pom`). These
break on real-world files (constraints files, multi-line specs, property
resolution, lockfile variants). Ecosystems are not independently installable;
no parser versioning, metadata, or discovery.

### A.1.8 No SBOM / policy / VEX capability
CycloneDX/SPDX, license compliance, VEX, custom advisories, policy engine —
all of requirement 7 — do not exist. "SCA scanner" framing implies SBOM.

### A.1.9 Cloud sync is "download a giant file or rebuild from NVD"
`cpe_index.py` `download_index()` streams the whole DB (1.5 GB) with only a
size + table sanity check. **No checksum, no digital signature, no versioning,
no rollback, no incremental updates, no CDN, no offline bundle.** `sca.yml`
falls back to a 30–60 min full sync. A security scanner trusting an
unauthenticated 1.5 GB blob is a supply-chain risk: whoever controls the URL
can mark a real CVE "fixed" or "low risk".

### A.1.10 No configuration system
Everything is an env var (`AVIP_*`). No config file, no hierarchy
(CLI > env > file > default), no `depwolf config`, no per-org policy,
no secret handling.

### A.1.11 Security posture
- API keys read from env (`remediation.py:294`, `cpe_index.py:16`); missing key
  silently returns `None`.
- `urllib.request` direct with no signature/checksum verification of the
  primary data source.
- `sca.yml` scans the whole repo with no severity filter, config, or SBOM.

### A.1.12 CLI surface is minimal vs the stated goal
Missing `update`, `db`, `version`, `config`, `sbom`, `policy`, and
`--severity`, `--ignore-unfixed`, `--exit-code`, `--output`, `--offline`,
`--cache-dir`. Exit-code gating is duplicated in `_emit` and `_remediate`.

### A.1.13 Testing strategy does not protect the core value
21 tests pass, but the DB suite skips entirely unless `AVIP_DB_PATH` is
exported. No fixtures build an index; nothing tests `build_index` /
`download_index`; no golden files for reporters; no property tests for the
version engine (the most bug-prone code).

### A.1.14 Distribution is pip-only, single package
One `depwolf` package, no entry-point groups, no Docker, no binaries, no
plugin packaging. `requires-python = ">=3.11"` (goal: 3.12+). No ruff/mypy
config beyond `from __future__`.

## A.2 What is genuinely good (keep)
- **Risk model is explicit and deterministic** (`risk.py`): named factors,
  weights, contributors, SLA buckets.
- **The AVIP funnel concept is sound**; the filter classes map 1:1 to real
  FP classes.
- **Universal CVE extraction** (`ingest.py`) is a pragmatic MVP; dedupe with
  context merge is correct.
- **Version-range semantics** in `cpe_index._version_key` (epochs, letter
  suffixes) are well thought out.
- **Zero-dependency, pure-stdlib CLI** is a real supply-chain/distribution win.
- **SARIF 2.1.0 output** is correctly shaped for GitHub Code Scanning.
