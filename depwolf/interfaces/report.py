"""Output serialization: JSON, SARIF, and human table for depwolf."""

from __future__ import annotations

from collections.abc import Callable
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


_BOX = {
    "tl": "┌",
    "tr": "┐",
    "bl": "└",
    "br": "┘",
    "h": "─",
    "v": "│",
    "m": "┬",
    "b": "┤",
    "l": "├",
    "c": "┼",
    "t": "┴",
}
_MAXW = [17, 20, 12, 10, 7, 12, 11, 10]
_SEV_COLOR = {"Critical": "91", "High": "95", "Medium": "93", "Low": "94"}


def _color(text: str, code: str) -> str:
    return f"\x1b[{code}m{text}\x1b[0m"


def _table(
    headers: list[str],
    rows: list[list[str]],
    color: bool,
    style: Callable[[int, str, str], str] | None = None,
) -> list[str]:
    n = len(headers)
    widths = [max(len(h), 1) for h in headers]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(cell))
    for i in range(n):
        widths[i] = min(widths[i], _MAXW[i] if i < len(_MAXW) else 16)

    def line(tl: str, join: str, br: str) -> str:
        inner = _BOX[join].join(f"{_BOX['h'] * (w + 2)}" for w in widths)
        return _BOX[tl] + inner + _BOX[br]

    def fmt(cells: list[str], right: set[int], header: bool = False) -> str:
        parts = []
        for i, cell in enumerate(cells):
            s = cell if len(cell) <= widths[i] else cell[: max(1, widths[i] - 1)] + "…"
            s = s.ljust(widths[i]) if i not in right else s.rjust(widths[i])
            if header and color:
                s = _color(s, "1;4")
            elif style:
                s = style(i, s, cell)
            parts.append(f" {s} ")
        return _BOX["v"] + _BOX["v"].join(parts) + _BOX["v"]

    out = [line("tl", "m", "tr"), fmt(headers, set(), header=True), line("l", "c", "b")]
    out.extend(fmt(r, {4}) for r in rows)
    out.append(line("bl", "t", "br"))
    if color:
        out[0] = _color(out[0], "1")
        out[2] = _color(out[2], "1")
        out[-1] = _color(out[-1], "1")
    return out


def render_table(result: dict) -> str:
    import os
    import sys
    from collections import Counter

    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    lines: list[str] = []
    total = result.get("total_scanned", 0)
    reduction = result.get("reduction_rate")
    na_rate = result.get("not_applicable_rate")
    summary = (
        f" candidates: {total}   actionable: {result.get('actionable', result.get('found'))}   "
        f"not_applicable: {result.get('not_applicable')}   "
        f"risk_suppressed: {result.get('risk_suppressed')}\n"
        f" reduction: {reduction}%   (not_applicable: {na_rate}% · legacy fp-rate: "
        f"{result.get('false_positive_rate')}%)"
    )
    w = max(len(summary.splitlines()[0]), len(summary.splitlines()[1]), 44) + 1
    top = "╔" + "═" * (w + 2) + "╗"
    title = " DEPWOLF — prioritized findings".ljust(w + 2)
    lines.append(_color(top, "1;36") if color else top)
    lines.append(_color("║" + title + "║", "1;36") if color else "║" + title + "║")
    for row in summary.splitlines():
        pad = " " + row.ljust(w + 1)
        lines.append("║" + pad + "║")
    lines.append("╚" + "═" * (w + 2) + "╝")

    headers = ["CVE", "Package", "Version", "Severity", "Risk", "Fixed", "Priority", "Confidence"]
    rows: list[list[str]] = []
    for f in result.get("prioritized", []):
        assets = f.get("affected_assets")
        pkg = assets[0] if assets else (f.get("pkg") or "?")
        ver = f.get("installed_version") or f.get("version") or "-"
        sev = str(f.get("severity") or "?")
        risk = str(f.get("risk_score"))
        fixed = f.get("fixed_version") or "-"
        pp = f.get("patch_priority") or "-"
        conf = f.get("match_confidence") or "-"
        rows.append([str(f.get("cve_id", "?")), str(pkg), str(ver), sev, risk, str(fixed), str(pp), str(conf)])

    def _style(i: int, padded: str, raw: str) -> str:
        if i == 3:
            return _color(padded, _SEV_COLOR.get(raw, "0"))
        if i == 4:
            try:
                risk = float(raw)
            except (TypeError, ValueError):
                return padded
            return _color(padded, "91;1" if risk >= 80 else ("93" if risk >= 60 else "0"))
        return padded

    t = _table(headers, rows, color, _style if color else None)
    lines.extend(t)

    if result.get("filtered_details"):
        reasons = Counter(d.get("reason") for d in result["filtered_details"])
        foot = "Filtered: " + "  ·  ".join(f"{n}x {reason}" for reason, n in reasons.most_common())
        width = max(min(max(len(x) for x in t), 72), len(foot), 44)
        lines.append("")
        lines.append("┌" + "─" * (width + 2) + "┐")
        lines.append("│ " + foot.ljust(width) + " │")
        lines.append("└" + "─" * (width + 2) + "┘")
    return "\n".join(lines)
