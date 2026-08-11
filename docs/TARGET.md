# DepWolf — Target Architecture

Status: DRAFT v1 (design only, no code)
Related: `docs/REVIEW.md` (critical review), `docs/DECISIONS.md` (ADRs), `docs/ROADMAP.md` (phasing)

## B.0 Principles
1. **Security-tool integrity is a security property**: signed, versioned,
   checksum-verified index; least privilege; opt-in telemetry.
2. **Core offline-first**: local scan must never require the cloud. Cloud is an
   accelerator + org layer, not a dependency.
3. **The funnel and version engine are the crown jewels**: pure, composed,
   property-tested, policy-configurable.
4. **Plugins via entry points**, not hardcoded dicts.
5. **Clean Architecture**: domain has zero I/O; infrastructure implements ports;
   interfaces (CLI/API) are thin.

## B.1 Layered Architecture

```
interfaces/     CLI (click/argparse) + REST API (FastAPI) + console reporting
   └──►  application/   Use cases / orchestration (thin, DI)
            scan_project, ingest_report, sync_index, policy_eval,
            sbom_export, remediation
   └──►  domain/        Pure logic, no I/O
            models (Finding, Vulnerability, Product, VersionRange)
            funnel (Filter protocol + chain), risk, versions, policy
   └──►  infrastructure/ Adapters (implement ports)
            db/ (sqlite, postgres)  sync/ (http, s3, cdn, cache)
            parsers/ (plugins)  report/ (json, sarif, html, cdx, spdx, pdf)
            config, logging, telemetry, keyring
```
Dependency rule: interfaces -> application -> domain; infrastructure implements
ports. Nothing higher may import a lower concrete module.

## B.2 Key Ports

```python
class IndexStore(Protocol):
    def lookup_cves(self, product: str, version: str) -> list[Vulnerability]: ...
    def get_cve(self, cve_id: str) -> Vulnerability | None: ...
    def ignored(self) -> set[str]: ...
    def set_ignored(self, cve_id: str, ignored: bool) -> None: ...

class ParserPlugin(Protocol):
    name: str; ecosystems: list[str]; schema_version: int
    def handles(self, path: Path) -> bool: ...
    def parse(self, source: Path) -> list[ParsedDep]: ...

class ReportWriter(Protocol):
    name: str
    def render(self, report: ScanReport, meta: ReportMeta) -> str: ...

class IndexSync(Protocol):
    def remote_manifest(self) -> RemoteManifest: ...
    def fetch(self, version: str, to: Path) -> None: ...
    def verify(self, bundle: Path, manifest: RemoteManifest) -> bool: ...
```

## B.3 Database Schema (normalized)

```sql
CREATE TABLE cves (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    cvss_score REAL, cvss_severity TEXT,
    epss_score REAL, kev BOOLEAN DEFAULT 0,
    published_date TEXT, modified_date TEXT
);
CREATE INDEX idx_cves_score ON cves(cvss_score);

CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    vendor TEXT NOT NULL, product TEXT NOT NULL,
    os TEXT,  -- computed at build: linux/windows/any
    UNIQUE(vendor, product)
);

CREATE TABLE vuln_ranges (
    cve_id TEXT REFERENCES cves(cve_id),
    product_id INTEGER REFERENCES products(id),
    start_incl TEXT, start_excl TEXT, end_incl TEXT, end_excl TEXT
);
CREATE INDEX idx_ranges_product ON vuln_ranges(product_id);
CREATE INDEX idx_ranges_cve ON vuln_ranges(cve_id);

CREATE TABLE index_meta (
    key TEXT PRIMARY KEY, value TEXT
    -- schema_version, built_at, source, sha256, signature,
    -- previous_version, channel
);

-- Local user state (NOT shipped in the signed bundle)
CREATE TABLE suppressions (
    cve_id TEXT PRIMARY KEY, reason TEXT,
    expires_at TEXT, created_at TEXT
);
```
Compaction: `cves` (~300k) + `products` (~100k) + `vuln_ranges` (~800k)
instead of millions of duplicated rows.

## B.4 Data Flows

### Local scan
```
depwolf scan ./app --format sarif --policy enterprise.yml
  cli -> ScanProjectUseCase
    -> find_manifests() (respects .depwolfignore, cache)
    -> ParserEngine.dispatch(file) -> plugins -> ParsedDep[]
    -> IndexStore.lookup_cves(product, version)   (batch, one connection)
    -> dedupe -> AVIP Funnel.chain(each CVE)      (pure, policy-injected)
    -> RiskService.score(row)                     (weights from policy)
    -> PolicyEngine.apply(severity/threshold/suppress/VEX)
    -> RemediationService.attach(facts)           (AI summary optional)
    -> ReportService.write(format) -> file/stdout
    -> ExitCodePolicy.emit(rule)                  (0/1/2)
```

### Report ingestion
```
depwolf scan trivy.json --format json
  cli -> IngestReportUseCase
    -> schema detect (trivy/grype/snyk/depcheck/semgrep/codeql/sarif/text)
    -> typed ParserPlugin.handles(file) -> findings w/ pkg+version context
    -> same tail as local scan (funnel, risk, policy, remediation, report)
```

### Signed incremental sync
```
depwolf sync --check | depwolf update
  1 read local index_meta (schema, version, sha256, signature)
  2 GET {CDN}/index/latest.json                    (small manifest)
  3 compare versions -> no-op if current
  4 fetch delta/chunk manifest (incremental ranges)
  5 download chunks to cache dir (parallel, resumable)
  6 verify chunk SHA256, then whole-bundle SHA256
  7 verify Ed25519 signature (pinned public key + TOFU fingerprint)
  8 build into temp DB, VACUUM, swap atomically
  9 keep previous DB; rollback on any failure
 10 update index_meta (version, built_at, previous_version)
```
Offline or no URL: use cached/local DB; slow NVD rebuild kept only behind
`depwolf db build`.

## B.5 REST API (cloud, optional)

```
GET  /api/v1/db/latest.json                     -> manifest (version, sha256, sig, urls)
POST /api/v1/db/verify                          -> checksum + signature status
POST /api/v1/scan                               -> submit report or project tarball -> job_id
GET  /api/v1/scan/{job_id}                      -> results
GET  /api/v1/organizations/{org}/findings?severity=high&page=1
POST /api/v1/organizations/{org}/policy         (validate + store)
POST /api/v1/organizations/{org}/suppressions
POST /api/v1/organizations/{org}/vex
GET  /api/v1/sbom/{id}                          -> cyclonedx/spdx
POST /api/v1/notifications/{webhook}            (Slack/Teams/email on gate)
Auth: OAuth2 client-credentials for CI; org-scoped API keys; least privilege.
```

## B.6 CLI Surface (target)

```
depwolf scan [TARGET...]  [--format json|sarif|html|cyclonedx|spdx|table|pdf]
                           [--output FILE] [--severity critical,high]
                           [--ignore-unfixed] [--policy FILE]
                           [--exit-code 0|1] [--offline] [--cache-dir DIR]
depwolf sync   [--check] [--channel stable] [--rollback]
depwolf update [--to VERSION]
depwolf db     build|verify|info|repair
depwolf version
depwolf config init|get|set|validate|show
depwolf sbom   generate|enrich|export   (--format cyclonedx|spdx)
depwolf policy validate|export|import|test
depwolf ignore|unignore|suppress CVE
depwolf export REPORT [--format ...]
```

## B.7 Configuration Hierarchy
```
1 CLI flags                    (highest)
2 Environment DEPWOLF_* / AVIP_* (legacy aliases)
3 Repo config  .depwolf.toml    (per-project policy, ignores)
4 User config  $XDG_CONFIG_HOME/depwolf/config.toml
5 Defaults
Secrets: env or OS keyring only; `depwolf config show` redacts.
```

## B.8 Deployment
```
Offline/CI: pip install depwolf || docker run depwolf/depwolf || native binary
            + signed index from CDN (cache persisted across jobs)
Cloud: FastAPI (K8s) -> PostgreSQL (orgs, findings, policy)
       + Redis (jobs, cache, rate-limit)
       + S3/GCS/Azure Blob (reports, sboms, index bundles)
       + CDN for index chunks -> edge caching
       + cron builder: ingest NVD/EPSS/KEV -> sign -> publish
```

## B.9 CI/CD Architecture
```
main: lint (ruff, mypy) -> test (pytest matrix py3.12/3.13 x linux/win/mac,
      in-memory index fixtures) -> build (sdist, wheel, docker, PyInstaller
      binaries) -> publish (PyPI + GitHub Release + container registry)
index-builder (schedule): build DB -> sign -> upload -> bump latest.json
consumer templates: github-actions, jenkins, gitlab, azure-pipelines,
      bitbucket-pipelines
```

## B.10 Security Architecture
- Signed index bundle (Ed25519), pinned public key, chunk + whole checksums
- TLS everywhere; secrets via keyring/env only, redacted, never logged
- Least privilege: cloud service accounts scoped to bucket+db; CI tokens
  read-only for scans, write for reports
- Parsers isolated per-file; a broken plugin never kills a scan
- AI is best-effort, rate-limited, never trusted for facts
- Supply chain: dependabot/renovate, SBOM of depwolf itself, signed releases,
  reproducible builds
- Telemetry: opt-in only, no source code, explicit consent file

## B.11 Future Scaling
- Horizontal: per-manifest worker pool, batched index queries on one
  connection, threaded report generation
- Vertical: `vuln_ranges` indexes + prepared statements; precomputed range
  bounds for O(log n) lookups
- Cloud: queue jobs to workers (Redis + Arq), shard findings by org, CDN-cache
  index chunks
- Extensibility: parsers/reporters/policy backends via entry points; optional
  OPA/Rego backend for orgs that need it
