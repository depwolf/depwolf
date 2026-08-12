# depwolf

[![CI](https://img.shields.io/github/actions/workflow/status/depwolf/depwolf/ci.yml?branch=main&label=CI&logo=github)](https://github.com/depwolf/depwolf/actions)
[![Coverage](https://img.shields.io/codecov/c/github/depwolf/depwolf/main?label=coverage)](https://codecov.io/gh/depwolf/depwolf)
[![PyPI](https://img.shields.io/pypi/v/depwolf.svg?label=PyPI)](https://pypi.org/project/depwolf/)
[![Python](https://img.shields.io/pypi/pyversions/depwolf.svg)](https://pypi.org/project/depwolf/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Post-process **any scanner's output** — Trivy, Grype, Snyk, OWASP
dependency-check, Semgrep, CodeQL SARIF, or anything that emits CVE IDs — and
turn it into:

1. **AVIP false-positive reduction** — the deterministic funnel that removes
   FPs (wrong OS, version outside the affected range, not in your stack,
   ignored, low risk) using the local `cpe_index.db` NVD/EPSS/KEV index.
2. **AI-based remediation** — fixed version, patch commands, step-by-step plan,
   and an executive summary per finding (LLM narrative optional; facts stay
   DB-grounded).

The engine is the AVIP FP reducer extracted as a standalone, offline-first,
pure-Python CLI. It does **not** scan anything itself — it reduces and
remediates reports that already contain CVE IDs.

- **Deterministic core** — matching, risk, and version decisions are computed
  from the database; AI never invents versions or scores.
- **Zero runtime dependencies** — pure stdlib, Python >= 3.12.
- **Typed and tested** — `CVERepository` port isolates all SQL; CI enforces
  ruff, mypy, and >= 80% coverage on every PR.

## Pipeline

```
scanner output (JSON or TXT) ──> extract CVE findings ──> AVIP FP funnel ──> remediation
  Trivy / Grype / Snyk /              any CVE-YYYY-NNNN       deterministic       DB-grounded fixes
  dependency-check / SAST              + pkg/version context   (risk >= 35)        + AI summary (optional)
```

### The FP funnel

| Step | Decision | Basis |
|------|----------|-------|
| Product resolution | vendor/product aliasing + fuzzy match | `cpe_index.db` |
| Version range | start/end inclusive/exclusive | `cpe_index.db` |
| OS filter | Windows/Linux-only CVEs | vendor/product heuristics |
| In-stack check | affected product/version present in your stack | findings pkg+version |
| Ignore list | persistent `ignored_cves` table | `depwolf ignore` |
| Risk floor | risk score >= 35 to report | CVSS 0.3846 + EPSS 0.3077 + KEV 0.3077 |
| Triage | fix_now / fix_week / fix_month | risk thresholds 80 / 60 |

Risk score and every match/version decision are computed from the database —
AI (when enabled) writes summaries only.

## Install

```bash
pip install depwolf
```

From source (for development, see [CONTRIBUTING.md](CONTRIBUTING.md)):

```bash
python -m pip install -e ".[dev]"
```

Requires Python >= 3.12. One runtime dependency: `PyYAML` (policy files);
optional `cryptography` enables Ed25519-signed index manifests (`[sync]` extra).

## Data: cpe_index.db

The FP reducer reads a local SQLite index (`vendor, product, version_start/end,
cve_id, description, cvss_score, cvss_severity, epss_score, kev, published_date`).

- Out of the box: the first `depwolf sync` (or first `depwolf scan`) downloads a
  prebuilt index from the depwolf release CDN — no configuration needed.
- Override the source: `export AVIP_DB_URL=https://.../cpe_index.db`
- Point at an existing DB: `export AVIP_DB_PATH=/path/to/cpe_index.db`
- Build/refresh one from NVD + FIRST EPSS + CISA KEV: `depwolf sync --full` (needs internet)

The DB is not shipped with the package (1.5 GB, downloaded once).

## Usage

```bash
# Ingest a Trivy JSON scan, reduce FPs, and attach AI remediation
depwolf scan trivy.json --format table

# Any other scanner JSON (Grype, Snyk, dependency-check, CodeQL/Semgrep SARIF)
depwolf scan grype.json --format table
depwolf scan sast.sarif --format sarif > reduced.sarif

# Plain text / stdin (any tool that prints CVE IDs)
echo "CVE-2021-44228 log4j 2.14.1" | depwolf scan
depwolf scan scanner.txt --format json --save report.json

# Scan a directory of reports
depwolf scan ./reports/ --format table

# Build gate: exit 1 if any finding >= risk 60
depwolf scan trivy.json --threshold 60; echo $?

# Remediation for a specific CVE (or list of CVEs)
depwolf remediate CVE-2021-44228

# Refresh the local NVD/EPSS/KEV index
depwolf sync
# Verify index integrity (sha256 + optional Ed25519 signature)
depwolf sync --check
# Show index path, verification status, and stats
depwolf db

# Ignore / unignore a CVE (persists to ignored_cves in cpe_index.db)
depwolf ignore CVE-2021-44228
depwolf unignore CVE-2021-44228

# Re-render a saved JSON report as SARIF/table
depwolf export report.json --format sarif

# Version
depwolf --version
```

`scan` arguments: `--os linux|windows`, `--threshold N`, `--format json|sarif|table`,
`--stack <file>` (extra 'pkg version' context), `--save <path>`, `--no-remediate`.
Remediation is **on by default**.

### Output

- **JSON**: `prioritized[]` findings with `risk_score`, `severity`,
  `patch_priority`, `fixed_version`, `patch_commands`, `step_by_step_fix`,
  `remediation_summary`, plus funnel stats (`filtered_out`,
  `false_positive_rate`, `filtered_reasons`).
- **SARIF 2.1.0**: GitHub Code Scanning compatible (error/warning/note levels).
- **Table**: human-readable terminal output.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | clean — no findings at/above `--threshold` |
| 1 | findings at/above `--threshold` (gate fail) |
| 2 | usage/parse error |

## AI remediation

Facts (`fixed_version`, patch commands, affected range, CVSS/EPSS/KEV) come
**only** from `cpe_index.db`. To have the executive summary drafted by an LLM,
set `AVIP_OPENAI_API_KEY` (and optionally `AVIP_AI_MODEL`). The model receives
verified facts and is instructed not to invent versions; all matching and
remediation decisions remain deterministic.

## CI / DevSecOps

- **`.github/workflows/ci.yml`** — enforced gate on every push/PR: ruff, ruff
  format, mypy, pytest with coverage (>= 80%), and a wheel/sdist build with a
  fresh-venv smoke test, across Python 3.12/3.13 and Ubuntu/Windows.
- **`.github/workflows/sca.yml`** — depwolf dogfooding its own repo: runs
  `depwolf scan . --format sarif`, uploads SARIF to GitHub Code Scanning, and
  fails the build when the gate trips.
- **`.github/workflows/release.yml`** — tagging `v<version>` (must match
  `depwolf --version`) builds, attests, and publishes to PyPI with a GitHub
  Release and generated notes.
- **`dependabot`** keeps Python + GitHub Actions dependencies current.

## Input handling

- **JSON**: recursively walks the structure and pulls every `CVE-\d{4}-\d{4,7}`
  value (works for `VulnerabilityID`, `ruleId`, `id`, references, ...), with
  sibling context for package / version / severity / target.
- **TXT**: parses CVE IDs per line, optionally with a `pkg version` prefix.
- Anything that contains a CVE ID works.

## Project layout

```
depwolf/
  __init__.py        __version__ (single source of truth)
  domain/            pure logic: versions, matching, funnel, model, ports
    ports.py         CVERepository protocol (typed DB boundary)
    funnel.py        composable Filter/Funnel chain
    match.py         fuzzy product/version matching
    versions.py      Debian-style version comparison engine
    model.py         canonical finding/range data types
  application/       use-cases
    matcher.py       thin facade over the funnel (parse_stack, match_stack, ...)
    filters.py       the six funnel filters (invalid/not_found/os/ignored/stack/risk)
    remediation.py   DB-grounded fixes + optional AI narrative
    ingest.py        universal CVE extraction from any JSON/TXT
    risk.py          risk score = CVSS 0.3846 + EPSS 0.3077 + KEV 0.3077
  infrastructure/    sqlite store (SqliteIndexStore), DB seeding, sync
  interfaces/        CLI entry point, JSON/SARIF/table serialization
tests/               pytest suite (LOG4J_ROWS fixture data in conftest.py)
```

## Security & reporting

See [SECURITY.md](SECURITY.md) for responsible disclosure. Do not file public
issues for vulnerabilities.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) (Keep a Changelog, SemVer).
