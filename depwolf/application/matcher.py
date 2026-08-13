"""AVIP false-positive reduction + matching (ADR-014, ADR-017).

Resolves scanner/CVE candidates against the index, runs the filter funnel, and
keeps only findings worth acting on. The index is reached through the
``CVERepository`` port — the domain never touches SQL or connections here.

Phase 3 (batch): ``_build_plan`` resolves the whole stack and all its CVE
ranges in a constant number of repository calls, killing the per-dep
connection-per-call / N+1 LIKE pattern and the candidates-then-prioritize
double query.
"""

from __future__ import annotations

import logging
import re

from depwolf.application.filters import default_funnel_filters
from depwolf.domain.funnel import FilterContext, Funnel
from depwolf.domain.match import asset_matches, better_confidence, row_os
from depwolf.domain.model import (
    Asset,
    CVEReference,
    Dependency,
    Enrichment,
    Finding,
    RiskAssessment,
    VulnRange,
)
from depwolf.domain.policy import Policy, apply_policy, default_policy
from depwolf.domain.ports import CVERepository
from depwolf.domain.risk import RiskResult, calculate_risk
from depwolf.domain.versions import _version_in_range
from depwolf.infrastructure.store import SqliteIndexStore

logger = logging.getLogger(__name__)


def _repo(store: CVERepository | None) -> CVERepository:
    return store or SqliteIndexStore()


# ---- stack parsing -------------------------------------------------------


def parse_stack(text: str) -> list[dict]:
    """Parse a 'product version' stack text into asset dicts."""
    items = []
    for part in re.split(r"[\n,]+", text or ""):
        line = part.strip()
        if not line or line.startswith("#"):
            continue
        if re.match(r"^os\s*[:=]\s*\w+$", line, re.IGNORECASE):
            continue
        m = re.match(r"^([-a-zA-Z0-9._+@/]+(?:\s+[-a-zA-Z0-9._+@/]+)*)\s+([0-9][0-9a-zA-Z._+:-]*)$", line)
        if m:
            items.append({"product": m.group(1).strip(), "version": m.group(2).strip()})
        else:
            items.append({"product": line.strip(), "version": None})
    return items


def _assets(stack_text: str | None) -> list[Asset]:
    return [Asset(product=a["product"], version=a["version"]) for a in parse_stack(stack_text or "")]


def _enrich_asset_versions(assets: list[Asset], dep_index: dict | None) -> list[Asset]:
    """Backfill versions the stack parser could not resolve from the manifest scan.

    The stack text only carries a version when the parseable 'name version' line
    matched; lockfile-resolved versions that the parser dropped (scoped names,
    range specs, placeholders) are reattached here so the funnel's applicability
    check sees the canonical installed version. ``dep_index`` maps a dep name
    (or maven artifact / npm artifact) to the resolved manifest dependency.
    """
    if not dep_index:
        return assets
    out: list[Asset] = []
    for asset in assets:
        if asset.version is not None:
            out.append(asset)
            continue
        dep = dep_index.get(asset.product) or dep_index.get(str(asset.product).split(":")[-1])
        if dep and dep.get("version"):
            out.append(Asset(product=asset.product, version=dep["version"]))
        else:
            out.append(asset)
    return out


def _canonical_dep(product: str, dep_index: dict | None) -> dict | None:
    """The canonical manifest dependency for a matched stack product."""
    if not dep_index:
        return None
    return dep_index.get(product) or dep_index.get(str(product).split(":")[-1])


def extract_os(text: str) -> str | None:
    m = re.search(r"(?m)^os\s*[:=]\s*(linux|windows|any)\s*$", text or "", re.IGNORECASE)
    return m.group(1).lower() if m else None


# ---- ignore list ---------------------------------------------------------


def get_ignored_cves(db=None, store: CVERepository | None = None) -> set:
    if db is None:
        return _repo(store).all_ignored()
    return {r[0] for r in db.execute("SELECT cve_id FROM ignored_cves").fetchall()}


def ignore_cve(cve_id: str, store: CVERepository | None = None) -> dict:
    cve_id = cve_id.strip().upper()
    _repo(store).ignore(cve_id)
    return {"cve_id": cve_id, "ignored": True}


def unignore_cve(cve_id: str, store: CVERepository | None = None) -> dict:
    cve_id = cve_id.strip().upper()
    _repo(store).unignore(cve_id)
    return {"cve_id": cve_id, "ignored": False}


# ---- batch matching plan (Phase 3) ---------------------------------------


def _build_plan(assets: list[Asset], repo: CVERepository) -> tuple[dict[str, list[VulnRange]], dict[str, str]]:
    """One-pass plan: resolve every stack product and fetch all CVE ranges.

    Constant number of repository calls (2) regardless of stack size, instead
    of connection-per-dependency. Returns ``(cve_id -> ranges, cve_id ->
    best match confidence)``.
    """
    names = [a.product for a in assets]
    resolved = repo.resolve_products_many(names)
    products: list[tuple[str, str]] = []
    conf_by_product: dict[tuple[str, str], str] = {}
    for name in names:
        for pm in resolved.get(name, []):
            products.append((pm.vendor, pm.product))
            conf_by_product[(pm.vendor, pm.product)] = better_confidence(
                conf_by_product.get((pm.vendor, pm.product)), pm.confidence
            )
    by_product = repo.cves_for_products(products)
    plan: dict[str, list[VulnRange]] = {}
    confidences: dict[str, str] = {}
    for (vendor, product), ranges in by_product.items():
        conf = conf_by_product.get((vendor, product), "heuristic")
        for r in ranges:
            plan.setdefault(r.cve_id, []).append(r)
            confidences[r.cve_id] = better_confidence(confidences.get(r.cve_id), conf)
    return plan, confidences


def match_plan(stack_text: str, store: CVERepository | None = None) -> dict[str, list[VulnRange]]:
    """Public one-pass plan for a stack (shared by scanner and funnel)."""
    plan, _ = match_plan_full(stack_text, store)
    return plan


def match_plan_full(
    stack_text: str, store: CVERepository | None = None
) -> tuple[dict[str, list[VulnRange]], dict[str, str]]:
    """Plan plus per-CVE product-match confidence (exact/alias/canonical/fuzzy)."""
    repo = _repo(store)
    assets = _assets(stack_text)
    if not assets:
        return {}, {}
    return _build_plan(assets, repo)


# ---- matching ------------------------------------------------------------


def candidates_for_stack(stack_text: str, store: CVERepository | None = None) -> list[dict]:
    """Candidate CVEs that reference any product in the stack (version-agnostic)."""
    plan = match_plan(stack_text, store)
    fallback = "?"
    return [{"cve_id": cid, "product": fallback} for cid in plan]


def _entry_from_row(r: VulnRange, asset: dict) -> dict:
    cvss = r.cvss_score
    epss = r.epss_score
    kev = r.kev
    risk = calculate_risk(cvss=cvss, epss=epss, kev=kev, evidence_count=1)
    return {
        "cve_id": r.cve_id,
        "description": r.description[:200] if r.description else "",
        "cvss_score": cvss,
        "epss_score": epss,
        "kev": kev,
        "risk_score": risk.score,
        "severity": risk.severity,
        "asset": asset["product"],
        "asset_version": asset["version"],
        "published_date": r.published_date,
    }


def match_stack(stack_text: str, store: CVERepository | None = None) -> dict:
    repo = _repo(store)
    assets = _assets(stack_text)
    plan, _ = _build_plan(assets, repo) if assets else ({}, {})
    results: dict[str, dict] = {}
    for cve_id, rows in plan.items():
        for r in rows:
            if assets[0].version and not _version_in_range(
                assets[0].version,
                r.version_start_including,
                r.version_start_excluding,
                r.version_end_including,
                r.version_end_excluding,
            ):
                continue
            entry = _entry_from_row(r, {"product": assets[0].product, "version": assets[0].version})
            existing = results.get(cve_id)
            if existing is None or entry["risk_score"] > existing["risk_score"]:
                results[cve_id] = entry
    sorted_results = sorted(results.values(), key=lambda x: x["risk_score"], reverse=True)
    fix_now = [r for r in sorted_results if r["risk_score"] >= 80]
    fix_week = [r for r in sorted_results if 60 <= r["risk_score"] < 80]
    fix_month = [r for r in sorted_results if r["risk_score"] < 60]
    return {
        "total_nvd": len(sorted_results),
        "total_matched": len(sorted_results),
        "fix_now": fix_now[:5],
        "fix_week": fix_week[:5],
        "fix_month": fix_month[:5],
    }


# ---- funnel facade -------------------------------------------------------


def _build_entry(
    ctx: FilterContext,
    risk: RiskResult,
    ref: CVEReference,
    policy: Policy,
    dep_index: dict | None = None,
) -> tuple[dict, list[VulnRange]]:
    best = ctx.rows[0]
    for r in ctx.rows:
        rk = calculate_risk(cvss=r.cvss_score, epss=r.epss_score, kev=r.kev, evidence_count=1)
        if rk.score > risk.score:
            risk = rk
            best = r
    row = ctx.matched_row or best
    matched_assets = (
        [a for a in ctx.assets if a.product in ctx.affected_assets] if ctx.affected_assets else list(ctx.assets)
    )
    verdict = apply_policy(
        policy,
        cve_id=ctx.cve_id,
        risk_score=risk.score,
        severity=risk.severity,
        kev=best.kev,
        epss=best.epss_score,
        cvss=best.cvss_score,
        fixed_version=ref.fixed_version,
        scanner_severity=ref.severity,
    )
    enrichment = Enrichment(
        cve_id=ctx.cve_id,
        found=True,
        vendor=best.vendor,
        product=row.product,
        matched_ranges=list(ctx.rows),
        fixed_version=ref.fixed_version,
        affected_assets=[Asset(a.product, a.version) for a in matched_assets],
        description=row.description or "",
    )
    deps: list[Dependency] = []
    for a in matched_assets:
        dep = _canonical_dep(a.product, dep_index)
        deps.append(
            Dependency(
                name=a.product,
                version=dep.get("version") if dep and dep.get("version") else a.version,
                ecosystem=str(dep.get("ecosystem") or "unknown") if dep else "unknown",
                source=str(dep.get("manifest") or "stack") if dep else "stack",
                group=dep.get("group") if dep else None,
                manifest=dep.get("manifest") if dep else None,
                direct=dep.get("direct") if dep else None,
                path=tuple(dep["path"]) if dep and dep.get("path") else None,
                version_confidence=dep.get("version_confidence") if dep else ("EXACT" if a.version else "UNKNOWN"),
                version_source=dep.get("version_source")
                if dep
                else ("dependency_tree" if a.version else "unavailable"),
            )
        )
    finding = Finding(
        cve=ref,
        matched=True,
        affected_assets=deps,
        enrichment=enrichment,
        risk=RiskAssessment(
            score=risk.score,
            severity=risk.severity,
            confidence=risk.confidence,
            factors=risk.factors,
            contributors=risk.contributors,
        ),
        verdict=verdict,
    )
    entry = finding.to_entry_dict()
    entry["cvss_score"] = best.cvss_score
    entry["epss_score"] = best.epss_score
    entry["kev"] = best.kev
    entry["published_date"] = row.published_date
    if ctx.match_confidence:
        entry["match_confidence"] = ctx.match_confidence
    # Every finding that reaches this point passed the applicability check:
    # the installed version is known and falls inside an authoritative range.
    entry["applicable"] = "YES"
    entry["applicability_note"] = None
    entry["ecosystem"] = deps[0].ecosystem if deps else "unknown"
    entry["package"] = deps[0].name if deps else entry.get("pkg")
    if deps and deps[0].manifest:
        entry["manifest"] = deps[0].manifest
    return entry, list(ctx.rows)


def prioritize_cves(
    cve_ids: list[str],
    stack_text: str | None = None,
    os_filter: str | None = None,
    store: CVERepository | None = None,
    refs: list[CVEReference] | None = None,
    policy: Policy | None = None,
    plan: dict[str, list[VulnRange]] | None = None,
    plan_conf: dict[str, str] | None = None,
    deps_index: dict | None = None,
) -> dict:
    repo = _repo(store)
    assets = _enrich_asset_versions(_assets(stack_text), deps_index)
    if os_filter is None:
        os_filter = extract_os(stack_text) if stack_text else None
    ignored = repo.all_ignored()
    policy = policy or default_policy()

    # Phase 3: one-pass batch plan (stack resolve + ranges) then backfill any
    # CVE not present in the stack (so not_found/not_in_stack stay correct).
    # `plan` may be supplied by the scanner to avoid the double query.
    if plan is None:
        plan, confidences = _build_plan(assets, repo) if assets else ({}, {})
    else:
        confidences = dict(plan_conf or {})
    known = dict(plan)
    extras = [c.strip().upper() for c in cve_ids if c.strip().upper() not in known]
    if extras:
        known.update(repo.cves_for_ids(extras))

    ref_by_id = {r.cve_id.upper(): r for r in (refs or [])}
    funnel = Funnel(default_funnel_filters())
    filtered_out: list[dict] = []
    prioritized: list[dict] = []
    ranges_by_cve: dict[str, list[VulnRange]] = {}
    invalid = 0
    for raw in cve_ids:
        cve_id = raw.strip().upper()
        ctx = FilterContext(
            cve_id=cve_id,
            rows=known.get(cve_id, []),
            assets=assets,
            os_filter=os_filter,
            ignored=ignored,
            match_confidence=confidences.get(cve_id),
        )
        funnel.run(ctx)
        if ctx.dropped:
            if ctx.reason == "invalid_id":
                invalid += 1
            entry: dict[str, object] = {"cve_id": cve_id, "reason": ctx.reason, "detail": ctx.detail}
            if ctx.risk_score is not None:
                entry["risk_score"] = ctx.risk_score
            if ctx.severity is not None or ctx.reason == "os_mismatch":
                entry["severity"] = ctx.severity
            filtered_out.append(entry)
            continue
        risk = max(
            (calculate_risk(cvss=r.cvss_score, epss=r.epss_score, kev=r.kev, evidence_count=1) for r in ctx.rows),
            key=lambda rk: rk.score,
            default=None,
        )
        if risk is None:
            continue
        ref = ref_by_id.get(cve_id) or CVEReference(cve_id=cve_id)
        entry, ranges = _build_entry(ctx, risk, ref, policy, dep_index=deps_index)
        prioritized.append(entry)
        ranges_by_cve[cve_id] = ranges

    prioritized.sort(key=lambda x: x["risk_score"], reverse=True)
    filtered_count = len(filtered_out)
    ignored_count = sum(1 for x in filtered_out if x["reason"] == "ignored")
    reason_counts = _filter_breakdown(filtered_out)
    needs_verification = reason_counts.get("unresolved_version", 0)
    not_applicable = sum(
        reason_counts.get(r, 0)
        for r in ("invalid_id", "not_found", "os_mismatch", "not_in_stack", "unresolved_version")
    )
    risk_suppressed = reason_counts.get("low_risk", 0)
    total = len(cve_ids)
    reduction_rate = round(filtered_count / total * 100, 1) if total else 0.0
    not_applicable_rate = round(not_applicable / total * 100, 1) if total else 0.0
    return {
        "total_scanned": total,
        "invalid_ids": invalid,
        "found": len(prioritized),
        "actionable": len(prioritized),
        "filtered_out": filtered_count,
        "not_applicable": not_applicable,
        "needs_verification": needs_verification,
        "risk_suppressed": risk_suppressed,
        "ignored_count": ignored_count,
        "reduction_rate": reduction_rate,
        "not_applicable_rate": not_applicable_rate,
        "false_positive_rate": not_applicable_rate,  # legacy key: proven non-applicable only
        "prioritized": prioritized,
        "filtered_details": filtered_out,
        "filtered_reasons": reason_counts,
        "ranges": ranges_by_cve,
        "fix_now": [p for p in prioritized if p["risk_score"] >= 80][:5],
        "fix_week": [p for p in prioritized if 60 <= p["risk_score"] < 80][:5],
        "fix_month": [p for p in prioritized if p["risk_score"] < 60][:5],
    }


def _filter_breakdown(filtered: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for item in filtered:
        counts[item["reason"]] = counts.get(item["reason"], 0) + 1
    return counts


# ---- scanner adapters (post-process path) --------------------------------


def ingest_trivy(
    trivy_json: dict,
    stack_text: str | None = None,
    os_filter: str | None = None,
    store: CVERepository | None = None,
) -> dict:
    """Extract CVEs from a Trivy JSON scan and run the same priority funnel."""
    refs: list[CVEReference] = []
    for result in (trivy_json or {}).get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            cve_id = (vuln.get("VulnerabilityID") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue
            refs.append(
                CVEReference(
                    cve_id=cve_id,
                    pkg=vuln.get("PkgName"),
                    installed_version=vuln.get("InstalledVersion"),
                    fixed_version=vuln.get("FixedVersion"),
                    severity=vuln.get("Severity"),
                    target=result.get("Target"),
                    source="trivy",
                )
            )
    if not refs:
        return {
            "error": "No CVEs found in Trivy JSON",
            "prioritized": [],
            "filtered_details": [],
        }

    stack = stack_text
    if not stack:
        lines = [f"{r.pkg} {r.installed_version}".strip() for r in refs]
        stack = "\n".join(dict.fromkeys(line for line in lines if line))

    result = prioritize_cves([r.cve_id for r in refs], stack, os_filter, store=store, refs=refs)
    result["source"] = "trivy"
    return result


def check_cve(
    cve_id: str,
    stack_text: str | None = None,
    os_filter: str | None = None,
    store: CVERepository | None = None,
) -> dict:
    repo = _repo(store)
    assets = _assets(stack_text)
    if os_filter is None:
        os_filter = extract_os(stack_text) if stack_text else None
    rows = repo.cve(cve_id)
    if not rows:
        return {"cve_id": cve_id, "found": False, "affects_stack": False}
    if os_filter in ("linux", "windows"):
        os_rows = [r for r in rows if row_os(r) is None or row_os(r) == os_filter]
        if not os_rows:
            return {
                "cve_id": cve_id,
                "found": True,
                "affects_stack": False,
                "os_mismatch": True,
                "detail": f"Only affects the wrong OS (targeting {os_filter})",
            }
        rows = os_rows
    row = max(
        rows, key=lambda r: calculate_risk(cvss=r.cvss_score, epss=r.epss_score, kev=r.kev, evidence_count=1).score
    )
    cvss = row.cvss_score
    epss = row.epss_score
    kev = row.kev
    risk = calculate_risk(cvss=cvss, epss=epss, kev=kev, evidence_count=1)
    affects = False
    affected_assets = []
    if assets:
        for asset in assets:
            if any(asset_matches(asset, r) for r in rows):
                affects = True
                affected_assets.append(asset.product)
    priority, sla = compute_priority_for(risk.score, kev, epss, cvss)
    return {
        "cve_id": cve_id,
        "found": True,
        "description": row.description[:200] if row.description else "",
        "cvss_score": cvss,
        "epss_score": epss,
        "kev": kev,
        "risk_score": risk.score,
        "severity": risk.severity,
        "patch_priority": priority,
        "patch_sla_hours": sla,
        "affects_stack": affects,
        "affected_assets": affected_assets,
    }


def compute_priority_for(score: float, kev: bool, epss: float | None, cvss: float | None) -> tuple[str, int]:
    from depwolf.domain.priority import compute_patch_priority

    return compute_patch_priority(score, kev, epss, cvss)
