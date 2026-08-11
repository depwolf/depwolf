"""Finding ingestion for the depwolf CLI.

Dispatch is adapter-first (``depwolf.application.adapters``): Trivy, Grype,
Snyk, OWASP dependency-check, Semgrep, CodeQL, and generic SARIF each get a
typed adapter emitting ``CVEReference`` with ``source``/``confidence``. The old
regex-heuristic walk survives as the low-confidence fallback (0.3) for any
report the adapters don't recognize. Plain text (anything that prints CVE IDs)
is handled here.
"""

from __future__ import annotations

import re

from depwolf.application.adapters import CVE_RE, extract_cves_typed
from depwolf.domain.model import CVEReference


def extract_cves(data) -> list[CVEReference]:
    """Typed extraction: adapters first, heuristic fallback, text support."""
    if isinstance(data, str):
        return _extract_text(data)
    return extract_cves_typed(data)


def extract_findings(data) -> list[dict]:
    """Extract findings as plain dicts (backward-compatible public API)."""
    return [c.to_dict() for c in extract_cves(data)]


def _extract_text(text: str) -> list[CVEReference]:
    refs: list[CVEReference] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        cves = [c.upper() for c in CVE_RE.findall(line)]
        if not cves:
            continue
        tokens = [t.strip(",;:") for t in line.split() if not CVE_RE.fullmatch(t)]
        pkg = None
        version = None
        if tokens:
            pkg = tokens[0]
            if len(tokens) > 1 and re.match(r"^[0-9]", tokens[1]):
                version = tokens[1]
        for c in cves:
            refs.append(
                CVEReference(
                    cve_id=c,
                    pkg=pkg,
                    installed_version=version,
                    source="text",
                    confidence=0.3,
                )
            )
    return refs


def dedupe(findings: list[dict]) -> list[dict]:
    """Keep one finding per CVE ID, merging context from later duplicates."""
    seen: dict[str, dict] = {}
    for f in findings:
        cve = (f.get("cve_id") or "").strip().upper()
        if not cve:
            continue
        f = dict(f)
        f["cve_id"] = cve
        if cve in seen:
            base = seen[cve]
            for k, v in f.items():
                if v not in (None, "", []) and base.get(k) in (None, "", []):
                    base[k] = v
            continue
        seen[cve] = f
    return list(seen.values())


def dedupe_cves(refs: list[CVEReference]) -> list[CVEReference]:
    """Keep one CVEReference per CVE ID, merging context from later duplicates."""
    seen: dict[str, CVEReference] = {}
    for r in refs:
        existing = seen.get(r.cve_id)
        if existing is None:
            seen[r.cve_id] = r
            continue
        seen[r.cve_id] = CVEReference(
            cve_id=r.cve_id,
            pkg=r.pkg or existing.pkg,
            installed_version=r.installed_version or existing.installed_version,
            fixed_version=r.fixed_version or existing.fixed_version,
            severity=r.severity or existing.severity,
            target=r.target or existing.target,
            source=existing.source,
            confidence=max(r.confidence, existing.confidence),
        )
    return list(seen.values())


def _pkg_of(f) -> str | None:
    if isinstance(f, CVEReference):
        return f.pkg
    return f.get("pkg") if isinstance(f, dict) else None


def _ver_of(f) -> str | None:
    if isinstance(f, CVEReference):
        return f.installed_version
    return f.get("installed_version") if isinstance(f, dict) else None


def findings_stack(findings) -> str:
    """Build a 'pkg version' stack text from findings for FP-reducer context."""
    lines = []
    for f in findings:
        pkg = _pkg_of(f)
        if not pkg:
            continue
        ver = _ver_of(f)
        line = f"{pkg} {ver}".strip() if ver else str(pkg)
        lines.append(line)
    return "\n".join(dict.fromkeys(line for line in lines if line))
