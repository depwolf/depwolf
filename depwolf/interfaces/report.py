"""Output serialization: JSON, SARIF, and human table for depwolf."""

from __future__ import annotations

from datetime import UTC, datetime

from depwolf import __version__


def build_json_report(result: dict, meta: dict | None = None) -> dict:
    out = dict(result)
    out["depwolf_version"] = __version__
    out["generated_at"] = datetime.now(UTC).isoformat()
    if meta:
        out["scan_meta"] = meta
    return out


def build_sarif(result: dict, tool_name: str = "depwolf") -> dict:
    """Convert a scan result into a SARIF 2.1.0 run (GitHub Code Scanning compatible)."""
    rules = {}
    results = []
    prioritized = result.get("prioritized", [])
    for i, f in enumerate(prioritized):
        rule_id = f.get("cve_id") or f"finding-{i}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": (f.get("description") or rule_id)[:200]},
                "fullDescription": {"text": (f.get("description") or "")[:4000]},
                "defaultConfiguration": {"level": _sarif_level(f.get("severity"))},
                "properties": {
                    "cvss_score": f.get("cvss_score"),
                    "epss_score": f.get("epss_score"),
                    "kev": f.get("kev"),
                    "risk_score": f.get("risk_score"),
                    "fixed_version": f.get("fixed_version"),
                    "patch_priority": f.get("patch_priority"),
                },
            }
        assets = f.get("affected_assets")
        asset = assets[0] if assets else (f.get("pkg") or "unknown")
        ver = f.get("installed_version")
        uri = f.get("target")
        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(f.get("severity")),
                "message": {"text": f"{rule_id} — {f.get('severity')} (risk {f.get('risk_score')}) in {asset}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri or "package"},
                            "region": {"startLine": 1, "startColumn": 1},
                            "properties": {"package": asset, "version": ver},
                        },
                    }
                ],
                "properties": {
                    "fixed_version": f.get("fixed_version"),
                    "patch_commands": f.get("patch_commands", []),
                    "remediation": f.get("remediation_summary"),
                },
            }
        )
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": __version__,
                        "informationUri": "https://github.com/depwolf/depwolf",
                        "rules": list(rules.values()),
                    },
                },
                "results": results,
            }
        ],
    }


def _sarif_level(severity: str | None) -> str:
    s = (severity or "").lower()
    if s in ("critical", "high"):
        return "error"
    if s == "medium":
        return "warning"
    return "note"


def render_table(result: dict) -> str:
    lines = []
    lines.append("=" * 90)
    lines.append(" DEPWOLF — prioritized findings")
    lines.append(
        f" total: {result.get('total_scanned')}  found: {result.get('found')}  "
        f"filtered: {result.get('filtered_out')}  fp-rate: {result.get('false_positive_rate')}%"
    )
    lines.append("=" * 90)
    header = f"{'CVE':<18}{'Pkg':<20}{'Sev':<10}{'Risk':<7}{'Fixed':<12}{'Patch'}"
    lines.append(header)
    lines.append("-" * 90)
    for f in result.get("prioritized", []):
        assets = f.get("affected_assets")
        pkg = assets[0] if assets else (f.get("pkg") or "?")
        sev = f.get("severity") or "?"
        risk = f.get("risk_score")
        fixed = f.get("fixed_version") or "-"
        pp = f.get("patch_priority") or "-"
        lines.append(f"{f.get('cve_id', '?'):<18}{str(pkg):<20}{str(sev):<10}{str(risk):<7}{str(fixed):<12}{pp}")
    if result.get("filtered_details"):
        lines.append("-" * 90)
        from collections import Counter

        reasons = Counter(d.get("reason") for d in result["filtered_details"])
        for reason, n in reasons.most_common():
            lines.append(f" filtered: {n}x {reason}")
    lines.append("=" * 90)
    return "\n".join(lines)
