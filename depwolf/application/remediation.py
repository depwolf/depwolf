"""Self-contained remediation for the depwolf CLI.

Grounded entirely in the local cpe_index.db (same version-range + risk engine as
AVIP). Optional LLM hook: when AVIP_AI_MODEL/AVIP_OPENAI_API_KEY are set, the AI
writes the full remediation narrative (executive summary, root cause,
step-by-step plan, verification) over verified DB facts; otherwise the
deterministic templates are used. Facts (fixed version, patch commands) always
come from the DB — never from the model.
"""

from __future__ import annotations

import os
import re

from depwolf.domain.model import VulnRange
from depwolf.domain.ports import CVERepository
from depwolf.domain.priority import compute_patch_priority
from depwolf.domain.risk import calculate_risk
from depwolf.domain.versions import _version_key
from depwolf.infrastructure.store import SqliteIndexStore

CWE_DESCRIPTIONS: dict[str, str] = {
    "CWE-79": "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)",
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
    "CWE-78": "Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)",
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
    "CWE-287": "Improper Authentication",
    "CWE-862": "Missing Authorization",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-611": "Improper Restriction of XML External Entity Reference",
    "CWE-94": "Improper Control of Generation of Code ('Code Injection')",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-77": "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
    "CWE-416": "Use After Free",
    "CWE-787": "Out-of-bounds Write",
    "CWE-1395": "Dependency on Vulnerable Third-Party Component",
}


def _bump_version(v: str) -> str:
    m = list(re.finditer(r"\d+", v))
    if not m:
        return v + "+"
    last = m[-1]
    bumped = str(int(last.group()) + 1)
    return v[: last.start()] + bumped + v[last.end() :]


def _fixed_of(r: VulnRange) -> str | None:
    if r.version_end_excluding:
        return r.version_end_excluding
    if r.version_end_including:
        return _bump_version(r.version_end_including)
    return None


def _range_str(row: VulnRange) -> str:
    parts = []
    if row.version_start_including:
        parts.append(f">= {row.version_start_including}")
    elif row.version_start_excluding:
        parts.append(f"> {row.version_start_excluding}")
    if row.version_end_including:
        parts.append(f"<= {row.version_end_including}")
    elif row.version_end_excluding:
        parts.append(f"< {row.version_end_excluding}")
    return " and ".join(parts) if parts else "all versions"


def _db_lookup(
    cve_id: str,
    store: CVERepository | None = None,
    rows: list[VulnRange] | None = None,
) -> dict | None:
    """Pull authoritative CVE facts from cpe_index.db (best-matching row).

    ``rows`` may be passed from an earlier batch match (the scan pipeline) to
    avoid a redundant DB re-query (ADR-017). Chooses the product named in the
    description (most precise); among that product's rows, picks the one with
    the highest fixed version. Falls back to the highest-CVSS product when the
    description names no product.
    """
    if rows is None:
        try:
            store = store or SqliteIndexStore()
            rows = store.cve(cve_id)
        except Exception:
            return None
    if not rows:
        return None

    desc = rows[0].description or ""

    best_product = None
    best_row = None
    for r in rows:
        product = (r.product or "").strip()
        if not product:
            continue
        norm = product.replace("_", " ").replace("-", " ").replace("/", " ").lower()
        if norm and norm in desc.lower():
            best_product = product
            break
    if best_product is None:
        best_product = max(rows, key=lambda r: r.cvss_score or 0.0).product

    cands = [r for r in rows if (r.product or "").strip() == best_product]
    with_fix = [r for r in cands if _fixed_of(r)]
    if with_fix:
        best_row = max(with_fix, key=lambda r: _version_key(_fixed_of(r) or ""))
    else:
        best_row = max(cands, key=lambda r: r.cvss_score or 0.0)

    cvss = best_row.cvss_score or 0.0
    epss = best_row.epss_score or 0.0
    kev = best_row.kev
    risk = calculate_risk(cvss=cvss, epss=epss, kev=kev, evidence_count=1)
    patch_priority, patch_sla_hours = compute_patch_priority(risk.score, kev, epss, cvss)

    version_rows = []
    seen = set()
    for r in cands:
        key = _range_str(r)
        if key in seen:
            continue
        seen.add(key)
        version_rows.append(_range_str(r))

    return {
        "description": desc,
        "cvss_score": cvss,
        "cvss_severity": best_row.cvss_severity or ("Unknown" if cvss == 0 else "High"),
        "epss_score": epss,
        "kev": kev,
        "risk_score": risk.score,
        "severity": risk.severity,
        "patch_priority": patch_priority,
        "patch_sla_hours": patch_sla_hours,
        "vendor": best_row.vendor or "Unknown",
        "product": best_product,
        "published_date": best_row.published_date,
        "affected_versions": version_rows[:25],
        "fixed_version": _fixed_of(best_row),
    }


def _package_name(product: str, vendor: str) -> str | None:
    known = {
        "log4j": "log4j-core",
        "nginx": "nginx",
        "openssl": "openssl",
        "postgresql": "postgresql",
        "redis": "redis",
        "node": "nodejs",
        "curl": "curl",
        "mysql": "mysql-server",
        "mongodb": "mongodb-org",
        "tomcat": "tomcat",
        "wordpress": "wordpress",
        "jenkins": "jenkins",
        "grafana": "grafana",
        "java": "openjdk",
        "python": "python3",
        "ruby": "ruby",
        "golang": "golang",
        "docker": "docker-ce",
        "kubernetes": "kubeadm",
        "xz": "xz-utils",
    }
    p = product.lower()
    for key, pkg in known.items():
        if key in p:
            return pkg
    return None


def _patch_commands(product: str, vendor: str, fixed_version: str | None, cve_id: str) -> list[str]:
    pl = product.lower()
    if "log4j" in pl:
        if fixed_version:
            return [
                f"# Maven: set log4j-core to {fixed_version} or later in pom.xml",
                f"<log4j.version>{fixed_version}</log4j.version>",
                "# Gradle: add to build.gradle",
                f"implementation 'org.apache.logging.log4j:log4j-core:{fixed_version}'",
                "# Or remove JndiLookup as a stopgap:",
                "zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class",
                "# Set JVM flag (defense in depth):",
                "-Dlog4j2.formatMsgNoLookups=true",
            ]
        return [
            "# No fixed version published. Remove JndiLookup as stopgap:",
            "zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class",
            "-Dlog4j2.formatMsgNoLookups=true",
        ]
    if "spring" in pl:
        return [
            "# Spring: upgrade framework/boot to patched release",
            "# Maven property in pom.xml:",
            "<spring-framework.version>5.3.18</spring-framework.version>",
            "# Or for Spring Boot:",
            "<spring-boot.version>2.6.6</spring-boot.version>",
        ]
    pkg = _package_name(product, vendor)
    if pkg:
        if fixed_version:
            return [
                "# Debian/Ubuntu",
                f"apt-get update && apt-get install --only-upgrade {pkg}",
                "# RHEL/CentOS",
                f"yum update {pkg}",
                "# Verify installed version",
                f"{pkg} --version | grep -E '[0-9]+\\.[0-9]+\\.[0-9]+'",
                f"# Confirm {cve_id} no longer reported",
                f"trivy image <image:tag> | grep -i {cve_id.lower()}",
            ]
        return [
            "# No fixed version published yet. Track the vendor advisory and:",
            f"apt-get update && apt-get install --only-upgrade {pkg}   # when patch lands",
            "# Or apply the mitigation described in the vendor advisory",
        ]
    return [
        "# No OS package maps to this product — remediate per the vendor advisory.",
        f"# Reference: {cve_id} advisory from {vendor}",
        "# Apply the vendor-supplied patch, or replace the affected component",
        f"# with a version that fixes {cve_id} (see fixed version below)",
    ]


def _executive_summary(cve_id, cvss, severity, vendor, product, is_kev, fixed_version=None):
    parts = [
        f"{cve_id} ({vendor} {product}) — CVSS {cvss} ({severity}).",
    ]
    if fixed_version:
        parts.append(f"Upgrade {product} to {fixed_version} or later to remediate.")
    else:
        parts.append("No fixed version published yet — follow the vendor advisory and apply mitigations.")
    if is_kev:
        parts.append("CRITICAL: Listed in CISA KEV. Remediate immediately.")
    else:
        parts.append("Not currently listed in CISA KEV. Remediate based on severity and exposure.")
    return " ".join(parts)


def _step_by_step(cve_id, is_kev, cvss, vendor, product, fixed_version):
    steps = [
        f"1. Inventory all systems running {vendor} {product}",
        "2. Check the currently installed version (see verification commands below)",
    ]
    if fixed_version:
        steps.append(f"3. Upgrade {product} to {fixed_version} or later (see patch commands below)")
    else:
        steps.append("3. No fixed version published yet — apply the vendor-recommended mitigation")
    steps += [
        "4. Test the upgrade in staging/non-production environment",
        "5. Schedule a maintenance window for production deployment",
        f"6. Apply the patch and verify {cve_id} is no longer reported",
    ]
    if is_kev:
        steps.insert(0, "0. IMMEDIATE: This CVE is in CISA KEV — expedite all steps")
    if cvss >= 9.0:
        steps.append("7. CRITICAL: Implement WAF rules or virtual patching until all systems are patched")
    return steps


def _root_cause(desc, vendor, product):
    snippet = (desc or "")[:2500] + ("..." if desc and len(desc) > 2500 else "")
    return f"The root cause in {vendor} {product} is: {snippet}"


def generate_remediation(cve_id: str, store: CVERepository | None = None) -> dict:
    """Generate remediation from cpe_index.db facts. Returns {} if CVE not in index."""
    facts = _db_lookup(cve_id, store=store)
    if not facts:
        return {"cve_id": cve_id, "found": False}
    is_kev = facts["kev"]
    fixed = facts["fixed_version"]
    cmds = _patch_commands(facts["product"], facts["vendor"], fixed, cve_id)
    summary = _executive_summary(
        cve_id,
        facts["cvss_score"],
        facts["cvss_severity"],
        facts["vendor"],
        facts["product"],
        is_kev,
        fixed,
    )
    ai = _ai_narrative(cve_id, facts)
    return {
        "cve_id": cve_id,
        "found": True,
        "description": facts["description"],
        "vendor": facts["vendor"],
        "product": facts["product"],
        "cvss_score": facts["cvss_score"],
        "cvss_severity": facts["cvss_severity"],
        "epss_score": facts["epss_score"],
        "kev": is_kev,
        "risk_score": facts["risk_score"],
        "severity": facts["severity"],
        "patch_priority": facts["patch_priority"],
        "fixed_version": fixed,
        "affected_versions": facts["affected_versions"],
        "patch_commands": cmds,
        "step_by_step_fix": (ai or {}).get("step_by_step_fix")
        or _step_by_step(cve_id, is_kev, facts["cvss_score"], facts["vendor"], facts["product"], fixed),
        "executive_summary": (ai or {}).get("executive_summary") or summary,
        "root_cause": (ai or {}).get("root_cause")
        or _root_cause(facts["description"], facts["vendor"], facts["product"]),
        "verification": (ai or {}).get("verification"),
        "remediation_source": "ai" if ai else "template",
    }


def _ai_narrative(cve_id: str, facts: dict) -> dict | None:
    """Full AI remediation narrative (JSON) over DB-verified facts.

    Returns a dict with executive_summary, root_cause, step_by_step_fix, and
    verification — or None when no API key is set or the model output is not
    usable. Fixed version / CVSS / patch commands are never sourced here; they
    stay DB-grounded so the model cannot invent them.
    """
    key = os.environ.get("AVIP_OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY")
    model = os.environ.get("AVIP_AI_MODEL") or "gpt-4o-mini"
    if not key:
        return None
    import json as _json
    import urllib.request

    prompt = (
        "You are a senior application security remediation engineer. Write the "
        "remediation for the vulnerability described below. Respond with a JSON "
        'object with exactly these keys: "executive_summary" (string, 3-4 '
        'sentences for a security engineer), "root_cause" (string, what causes '
        'it in the component), "step_by_step_fix" (list of strings, concrete '
        'ordered remediation steps), "verification" (string, how to confirm '
        "the fix worked). Be practical and specific to this finding. Never "
        "invent versions, CVSS scores, or fixed versions — use only the facts "
        "provided. Facts (verified): cve_id={cve_id} product={product} "
        "vendor={vendor} cvss={cvss} severity={severity} kev={kev} "
        "risk={risk} patch_priority={priority} "
        "fixed_version={fixed} affected_versions={versions} "
        "description={desc}."
    ).format(
        cve_id=cve_id,
        product=facts["product"],
        vendor=facts["vendor"],
        cvss=facts["cvss_score"],
        severity=facts["cvss_severity"],
        kev=facts["kev"],
        risk=facts["risk_score"],
        priority=facts["patch_priority"],
        fixed=facts["fixed_version"],
        versions=facts["affected_versions"],
        desc=(facts["description"] or "")[:1500],
    )
    body = _json.dumps(
        {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens": 700,
            "response_format": {"type": "json_object"},
        }
    ).encode()
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = _json.loads(resp.read())
        out = _json.loads(data["choices"][0]["message"]["content"])
        required = {"executive_summary", "root_cause", "step_by_step_fix", "verification"}
        if not required.issubset(out):
            return None
        return {
            "executive_summary": str(out.get("executive_summary", "")).strip(),
            "root_cause": str(out.get("root_cause", "")).strip(),
            "step_by_step_fix": [str(s) for s in out.get("step_by_step_fix", [])],
            "verification": str(out.get("verification", "")).strip(),
        }
    except Exception:
        return None
