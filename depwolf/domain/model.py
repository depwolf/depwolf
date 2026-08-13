"""Canonical domain model for depwolf (ADR-017).

Everything flows through these types. Adapters produce ``CVEReference`` /
``Finding`` objects; downstream stages (enrichment, funnel, risk, policy,
remediation, reporting) consume them. No module other than the owning adapter
understands a raw scanner JSON schema. The index (DB) boundary is typed by
``VulnRange`` and ``ProductMatch`` so the domain never touches SQL.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from depwolf.domain.risk import RiskFactor


@dataclass(frozen=True)
class Dependency:
    """A resolved dependency from a manifest (native scan path)."""

    name: str
    version: str | None
    ecosystem: str
    source: str  # manifest path or scan target
    group: str | None = None  # maven groupId / npm scope / go module namespace
    manifest: str | None = None  # exact manifest path
    direct: bool | None = None  # True=direct, False=transitive, None=unknown
    path: tuple[str, ...] | None = None  # dependency path (top-down), when known
    version_confidence: str | None = None  # EXACT | INFERRED | UNKNOWN
    version_source: str | None = None  # manifest | lockfile | scanner_report | dependency_tree | inferred

    @property
    def dependency_type(self) -> str:
        """DIRECT when explicitly declared, TRANSITIVE when pulled in, else UNKNOWN."""
        if self.direct is True:
            return "DIRECT"
        if self.direct is False:
            return "TRANSITIVE"
        return "UNKNOWN"


@dataclass(frozen=True)
class CVEReference:
    """A CVE as reported by a scanner or extracted from a manifest."""

    cve_id: str
    pkg: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    severity: str | None = None
    target: str | None = None
    source: str = "unknown"
    # trivy | grype | snyk | sarif | codeql | semgrep | dependency-check | text | heuristic | manifest
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "pkg": self.pkg,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "severity": self.severity,
            "target": self.target,
            "source": self.source,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CVEReference:
        return cls(
            cve_id=str(d.get("cve_id", "")).strip().upper(),
            pkg=d.get("pkg"),
            installed_version=d.get("installed_version"),
            fixed_version=d.get("fixed_version"),
            severity=d.get("severity"),
            target=d.get("target"),
            source=str(d.get("source") or "unknown"),
            confidence=float(d.get("confidence") or 1.0),
        )


@dataclass
class Enrichment:
    """Index-backed facts attached to a finding after matching."""

    cve_id: str
    found: bool = False
    vendor: str | None = None
    product: str | None = None
    matched_ranges: list[VulnRange] = field(default_factory=list)
    fixed_version: str | None = None
    affected_assets: list[Asset] = field(default_factory=list)
    description: str = ""


@dataclass(frozen=True)
class RiskAssessment:
    """The deterministic risk score for a finding (no policy inputs)."""

    score: float
    severity: str
    confidence: float
    factors: dict[str, float]
    contributors: list[RiskFactor]


@dataclass(frozen=True)
class PolicyVerdict:
    """Outcome of applying a policy to a finding."""

    decision: str  # "allow" | "warn" | "deny"
    reason: str
    rule: str | None = None
    patch_priority: str | None = None
    sla_hours: int | None = None


@dataclass
class Remediation:
    """DB-grounded remediation for one CVE (facts only; AI writes narrative)."""

    cve_id: str
    found: bool = False
    vendor: str | None = None
    product: str | None = None
    description: str = ""
    cvss_score: float = 0.0
    cvss_severity: str = ""
    epss_score: float = 0.0
    kev: bool = False
    risk_score: float = 0.0
    severity: str = ""
    fixed_version: str | None = None
    affected_versions: list[str] = field(default_factory=list)
    patch_commands: list[str] = field(default_factory=list)
    step_by_step_fix: list[str] = field(default_factory=list)
    executive_summary: str = ""
    root_cause: str = ""
    verification: str | None = None
    source: str = "template"  # "ai" | "template"


@dataclass
class Finding:
    """Canonical finding consumed by every downstream stage."""

    cve: CVEReference
    matched: bool = False
    affected_assets: list[Dependency] = field(default_factory=list)
    enrichment: Enrichment | None = None
    risk: RiskAssessment | None = None
    verdict: PolicyVerdict | None = None
    remediation: Remediation | None = None

    def to_entry_dict(self) -> dict[str, Any]:
        """Canonical CLI/report entry. Every consumer reads these keys only."""
        e: dict[str, Any] = {
            "cve_id": self.cve.cve_id,
            "pkg": self.cve.pkg,
            "installed_version": self.cve.installed_version,
            "fixed_version": self.cve.fixed_version,
            "scanner_severity": self.cve.severity,
            "target": self.cve.target,
            "source": self.cve.source,
            "confidence": self.cve.confidence,
            "affected_assets": [a.name for a in self.affected_assets],
        }
        if self.affected_assets:
            dep = self.affected_assets[0]
            if not e.get("installed_version") and dep.version:
                e["installed_version"] = dep.version
            if dep.version_confidence:
                e["version_confidence"] = dep.version_confidence
            if dep.version_source:
                e["version_source"] = dep.version_source
            e["dependency_type"] = dep.dependency_type
            if dep.path:
                e["dependency_path"] = list(dep.path)
        if self.enrichment:
            e["found"] = self.enrichment.found
            e["vendor"] = self.enrichment.vendor
            e["product"] = self.enrichment.product
            e["description"] = (self.enrichment.description or "")[:200]
            e["published_date"] = (
                self.enrichment.matched_ranges[0].published_date if self.enrichment.matched_ranges else None
            )
            e["cvss_score"] = (
                max((r.cvss_score or 0.0) for r in self.enrichment.matched_ranges)
                if self.enrichment.matched_ranges
                else 0.0
            )
            e["epss_score"] = (
                max((r.epss_score or 0.0) for r in self.enrichment.matched_ranges)
                if self.enrichment.matched_ranges
                else 0.0
            )
            e["kev"] = any(r.kev for r in self.enrichment.matched_ranges)
            if not e["fixed_version"]:
                e["fixed_version"] = self.enrichment.fixed_version
        if self.risk:
            e["risk_score"] = self.risk.score
            e["severity"] = self.risk.severity
        if self.verdict:
            e["patch_priority"] = self.verdict.patch_priority
            e["patch_sla_hours"] = self.verdict.sla_hours
            e["verdict"] = self.verdict.decision
            e["verdict_reason"] = self.verdict.reason
        if self.remediation:
            e["remediation_summary"] = self.remediation.executive_summary
            e["root_cause"] = self.remediation.root_cause
            e["step_by_step_fix"] = self.remediation.step_by_step_fix
            e["patch_commands"] = self.remediation.patch_commands
            e["verification"] = self.remediation.verification
            e["remediation_source"] = self.remediation.source
            e["affected_versions"] = self.remediation.affected_versions
        return e


@dataclass(frozen=True)
class Asset:
    """A parsed stack item (product + optional installed version)."""

    product: str
    version: str | None


@dataclass(frozen=True)
class ProductMatch:
    """A resolved (vendor, product) pair for a stack product.

    ``confidence`` reflects how the stack name was matched to the index product:
    exact / alias / canonical / fuzzy / heuristic.
    """

    vendor: str
    product: str
    confidence: str = "fuzzy"


@dataclass(frozen=True)
class VulnRange:
    """One vulnerable version range from the index (typed DB row)."""

    cve_id: str
    vendor: str
    product: str
    version_start_including: str | None
    version_start_excluding: str | None
    version_end_including: str | None
    version_end_excluding: str | None
    description: str
    cvss_score: float
    cvss_severity: str
    epss_score: float
    kev: bool
    published_date: str | None
