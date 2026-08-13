"""depwolf CLI — post-process any scanner output into FP-reduced, AI-remediated findings.

Pipeline: read scanner output (JSON or TXT, from Trivy / Grype / Snyk / OWASP
dependency-check / Semgrep / CodeQL SARIF, or anything that emits CVE IDs)
-> extract findings -> AVIP false-positive reduction funnel (deterministic,
DB-grounded) -> remediation (DB-grounded fixes + optional AI executive summary).

Commands:
  scan <input...>          run the full pipeline on one or more scanner reports
  remediate <CVE...>       remediation only, for direct CVE IDs
  verify <CVE...>          FIXED / STILL VULNERABLE / UNABLE TO VERIFY verdict
  sync                     build/refresh cpe_index.db from NVD/EPSS/KEV (internet)
  ignore / unignore <CVE>  persist CVEs to the ignore list
  export <report.json>     re-render a saved JSON report as SARIF/table

Exit codes: 0 = clean/no findings, 1 = findings at/above gate, 2 = error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from depwolf import __version__
from depwolf.application.ingest import dedupe_cves, extract_cves, findings_stack
from depwolf.application.matcher import ignore_cve, prioritize_cves, unignore_cve
from depwolf.application.remediation import generate_remediation, verify_fix
from depwolf.domain.model import CVEReference
from depwolf.infrastructure.cpe_index import DB_PATH
from depwolf.interfaces.report import (
    build_json_report,
    build_sarif,
    render_remediation_table,
    render_table,
)

_REPORT_EXTS = (".json", ".txt", ".sarif")
_SKIP_DIRS = {
    "node_modules",
    ".git",
    "__pycache__",
    "dist",
    "build",
    ".venv",
    "venv",
    "target",
    ".idea",
    ".vscode",
    "site-packages",
    "dist-info",
    "egg-info",
    ".egg-info",
}


def _parse_text_or_json(text: str):
    text = text.lstrip("\ufeff")  # tolerate a UTF-8 BOM
    t = text.lstrip()
    if t.startswith("{") or t.startswith("["):
        try:
            return json.loads(t)
        except json.JSONDecodeError as e:
            raise ValueError(f"invalid JSON input: {e}") from e
    return text


def _read_input(path: str):
    if path == "-":
        try:
            return _parse_text_or_json(sys.stdin.read())
        except ValueError as e:
            raise SystemExit(f"error: {e}") from e
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"error: no such file or directory: {p}")
    return _parse_text_or_json(p.read_text(encoding="utf-8-sig", errors="replace"))


def _find_report_files(root: Path):
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() in _REPORT_EXTS:
            yield p


def _collect_findings(inputs: list[str]) -> list[CVEReference]:
    findings: list[CVEReference] = []
    for path in inputs:
        if path == "-":
            data = _read_input("-")
            findings.extend(extract_cves(data))
            continue
        p = Path(path)
        if p.is_dir():
            for report in _find_report_files(p):
                try:
                    data = _read_input(str(report))
                    found = extract_cves(data)
                    findings.extend(found)
                    if found:
                        print(f"[scan] {report}: {len(found)} finding(s)", file=sys.stderr)
                except Exception as e:
                    print(f"[warn] could not read {report}: {e}", file=sys.stderr)
        else:
            data = _read_input(str(p))
            findings.extend(extract_cves(data))
    return dedupe_cves(findings)


def _remediation_context(dep_index: dict, entry: dict) -> dict | None:
    assets = entry.get("affected_assets") or []
    asset = assets[0] if assets else entry.get("pkg")
    dep = (dep_index.get(str(asset)) if asset else None) or dep_index.get(str(entry.get("pkg") or ""))
    if not dep:
        return None
    return {
        "installed_version": dep.get("version"),
        "ecosystem": dep.get("ecosystem"),
        "name": dep.get("name"),
        "group": dep.get("group"),
        "artifact": dep.get("artifact") or dep.get("name"),
        "manifest": dep.get("manifest"),
        "direct": dep.get("direct"),
        "path": dep.get("path"),
    }


def _attach_remediation(entries: list[dict], dep_index: dict | None = None) -> None:
    seen = set()
    for entry in entries:
        cve = entry.get("cve_id")
        if not cve or cve in seen:
            continue
        seen.add(cve)
        rem = generate_remediation(cve, context=_remediation_context(dep_index or {}, entry))
        if rem.get("found"):
            entry["remediation_summary"] = rem.get("executive_summary")
            entry["root_cause"] = rem.get("root_cause")
            entry["vendor"] = rem.get("vendor")
            entry["product"] = rem.get("product")
            entry["affected_versions"] = rem.get("affected_versions")
            entry["fixed_version"] = rem.get("fixed_version") or entry.get("fixed_version")
            entry["minimum_safe_version"] = rem.get("minimum_safe_version")
            entry["recommended_action"] = rem.get("recommended_action")
            entry["patch_commands"] = rem.get("patch_commands")
            entry["file_change"] = rem.get("file_change")
            entry["compatibility_warning"] = rem.get("compatibility_warning")
            entry["transitive_explanation"] = rem.get("transitive_explanation")
            entry["step_by_step_fix"] = rem.get("step_by_step_fix")
            entry["verification"] = rem.get("verification")
            entry["remediation_source"] = rem.get("remediation_source")
            if rem.get("ecosystem"):
                entry["ecosystem"] = rem.get("ecosystem")
            if rem.get("installed_version"):
                entry["installed_version"] = rem.get("installed_version")


def _require_db() -> bool:
    import sqlite3 as _sqlite3

    if not DB_PATH.exists():
        from depwolf.infrastructure.cpe_index import download_index

        print(f"[sync] no local CVE index found; downloading prebuilt index to {DB_PATH}...", file=sys.stderr)
        print("[sync] one-time download (~1.5 GB). This happens only on first run.", file=sys.stderr)
        if download_index():
            print(f"[sync] downloaded prebuilt index to {DB_PATH}", file=sys.stderr)
        else:
            print(f"error: no CVE index found at {DB_PATH}", file=sys.stderr)
            print("hint: check your internet connection and retry,", file=sys.stderr)
            print("      or set AVIP_DB_URL to a prebuilt cpe_index.db URL,", file=sys.stderr)
            print("      or set AVIP_DB_PATH to an existing cpe_index.db", file=sys.stderr)
            return False
    try:
        db = _sqlite3.connect(str(DB_PATH))
        row = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cpe_index'").fetchone()
        count = db.execute("SELECT COUNT(*) FROM cpe_index").fetchone()[0] if row else 0
        db.close()
    except Exception:
        row = None
        count = 0
    if not row or count == 0:
        if row and count == 0:
            from depwolf.infrastructure.cpe_index import download_index

            msg = f"[sync] index at {DB_PATH} is empty ({count} rows); re-downloading prebuilt index..."
            print(msg, file=sys.stderr)
            try:
                DB_PATH.unlink()
            except OSError:
                pass
            if download_index():
                print(f"[sync] downloaded prebuilt index to {DB_PATH}", file=sys.stderr)
                return True
        print(f"error: {DB_PATH} has no usable index (empty or missing cpe_index table)", file=sys.stderr)
        print("hint: run 'depwolf sync' to download/rebuild it, or set AVIP_DB_PATH to a valid index", file=sys.stderr)
        return False
    return True


def _scan(inputs, os_filter, threshold, with_remediation, fmt, save_path, stack_path) -> int:
    if not _require_db():
        return 2

    from depwolf.application.scanner import collect_project

    native = None
    report_inputs = []
    for path in inputs:
        if path == "-":
            report_inputs.append(path)
            continue
        p = Path(path)
        if p.is_dir():
            collected = collect_project(p)
            if not collected.get("error"):
                native = _merge_native(native, collected)
            report_inputs.append(str(p))
        else:
            report_inputs.append(path)

    findings = _collect_findings(report_inputs)
    cve_ids = [f.cve_id for f in findings]
    if native:
        for cid in native["cve_ids"]:
            if cid not in cve_ids:
                cve_ids.append(cid)

    if not cve_ids:
        print("[scan] no CVE IDs found in the given input", file=sys.stderr)
        empty = {
            "total_scanned": 0,
            "found": 0,
            "prioritized": [],
            "filtered_out": 0,
            "false_positive_rate": 0.0,
            "filtered_details": [],
        }
        return _emit(empty, threshold, fmt, save_path)

    stack = ""
    if stack_path:
        sp = Path(stack_path)
        if not sp.exists():
            raise SystemExit(f"error: no such stack file: {sp}")
        stack = sp.read_text(encoding="utf-8", errors="replace")
    else:
        stack = findings_stack(findings)
        if native:
            native_stack = native.get("stack") or ""
            stack = "\n".join(dict.fromkeys((native_stack + "\n" + stack).splitlines()))

    result = prioritize_cves(
        cve_ids,
        stack or None,
        os_filter,
        refs=findings,
        plan=native and native.get("plan"),
        plan_conf=native and native.get("plan_conf"),
    )

    result["total_scanned"] = len(cve_ids)
    result["found"] = len(result.get("prioritized", []))
    result["source"] = "manifest-scan" if native else "scanner-output"
    result["scanner_findings"] = [f.to_dict() for f in findings]
    if native:
        result["manifests"] = native["manifests"]
        result["deps"] = native["deps"]

    if with_remediation:
        dep_index = None
        if native:
            dep_index = {}
            for d in native["deps"]:
                dep_index[d["name"]] = d
                if d.get("artifact"):
                    dep_index.setdefault(d["artifact"], d)
        _attach_remediation(result.get("prioritized", []), dep_index)
    else:
        print("[scan] remediation skipped (--no-remediate)", file=sys.stderr)

    return _emit(result, threshold, fmt, save_path)


def _merge_native(a: dict | None, b: dict) -> dict:
    if a is None:
        return b
    plan = dict(a.get("plan") or {})
    for cve_id, rows in (b.get("plan") or {}).items():
        plan.setdefault(cve_id, rows)
    plan_conf = dict(a.get("plan_conf") or {})
    plan_conf.update(b.get("plan_conf") or {})
    return {
        "manifests": a["manifests"] + b["manifests"],
        "deps": a["deps"] + b["deps"],
        "stack": "\n".join(dict.fromkeys((a["stack"] + "\n" + b["stack"]).splitlines())),
        "cve_ids": list(dict.fromkeys(a["cve_ids"] + b["cve_ids"])),
        "plan": plan,
        "plan_conf": plan_conf,
    }


def _emit(result: dict, threshold: int, fmt: str, save_path: str | None = None) -> int:
    report = build_json_report(result)
    if save_path:
        Path(save_path).write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        print(f"[report] saved to {save_path}", file=sys.stderr)
    if fmt == "sarif":
        print(json.dumps(build_sarif(result), indent=2))
    elif fmt == "table":
        print(render_table(result))
    else:
        print(json.dumps(report, indent=2, default=str))
    prioritized = result.get("prioritized") or []
    high = [f for f in prioritized if (f.get("risk_score") or 0) >= threshold]
    if high:
        print(f"\n[gate] {len(high)} finding(s) at/above risk threshold {threshold} — FAIL", file=sys.stderr)
        return 1
    print(f"\n[gate] no findings at/above risk threshold {threshold} — PASS", file=sys.stderr)
    return 0


def _remediate(cves: list[str], threshold: int, fmt: str = "table") -> int:
    if not _require_db():
        return 2
    results = []
    for cve in cves:
        results.append(generate_remediation(cve))
    if fmt == "table":
        print(render_remediation_table(results, threshold))
    else:
        out = build_json_report({"remediation": results})
        print(json.dumps(out, indent=2, default=str))
    found = [r for r in results if r.get("found") and (r.get("risk_score") or 0) >= threshold]
    if found:
        gate = f"[gate] {len(found)} remediated finding(s) at/above risk threshold {threshold} — remediate"
        print(gate, file=sys.stderr)
        return 1
    print(f"[gate] no findings at/above risk threshold {threshold} — PASS", file=sys.stderr)
    return 0


def _verify(cves: list[str], version: str | None) -> int:
    if not _require_db():
        return 2
    results = []
    for cve in cves:
        status = verify_fix(cve, version)
        results.append({"cve_id": cve, "installed_version": version, "status": status})
        print(f"{cve}: {status.replace('_', ' ').upper()}")
    if version is None:
        print(
            "note: pass --version <installed> to get a definitive FIXED / STILL VULNERABLE verdict; "
            "without it the status is always UNABLE TO VERIFY (never treated as FIXED).",
            file=sys.stderr,
        )
    print(json.dumps(results, indent=2, default=str))
    return 0


def _sync(check: bool = False, full: bool = False) -> int:
    import logging

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
    from depwolf.infrastructure.cpe_index import build_index, verify_index

    if check:
        ok, detail = verify_index(DB_PATH)
        if ok:
            print(f"[sync] index OK at {DB_PATH} ({detail})", file=sys.stderr)
            return 0
        print(f"[sync] index INVALID at {DB_PATH}: {detail}", file=sys.stderr)
        print("hint: run 'depwolf sync' to rebuild, or 'depwolf sync --verify' to re-check", file=sys.stderr)
        return 1
    if full:
        print("Syncing cpe_index.db from NVD/EPSS/KEV (full rebuild)...", file=sys.stderr)
    elif os.environ.get("AVIP_DB_URL"):
        print("Syncing cpe_index.db from AVIP_DB_URL (prebuilt index)...", file=sys.stderr)
    else:
        print(f"Syncing cpe_index.db ({DB_PATH}) — downloading prebuilt index by default...", file=sys.stderr)
    build_index(full_sync=full)
    return 0


def _db_info() -> int:
    from depwolf.infrastructure.cpe_index import index_stats, verify_index

    if not DB_PATH.exists():
        print(f"error: no CVE index at {DB_PATH}", file=sys.stderr)
        print("hint: run 'depwolf sync' to build it, or set AVIP_DB_PATH", file=sys.stderr)
        return 2
    ok, detail = verify_index(DB_PATH)
    if not ok:
        print(f"error: index at {DB_PATH} is INVALID: {detail}", file=sys.stderr)
        return 1
    stats = index_stats(DB_PATH)
    print(
        json.dumps(
            {
                "db_path": str(DB_PATH),
                "verified": True,
                "check": detail,
                "stats": stats,
            },
            indent=2,
            default=str,
        )
    )
    return 0


def _ignore(cves: list[str], unignore: bool) -> int:
    if not _require_db():
        return 2
    out = []
    for cve in cves:
        out.append(unignore_cve(cve) if unignore else ignore_cve(cve))
    print(json.dumps(out, indent=2))
    return 0


def _export(path: Path, fmt: str) -> int:
    data = json.loads(path.read_text(encoding="utf-8"))
    if fmt == "sarif":
        print(json.dumps(build_sarif(data), indent=2))
    elif fmt == "table":
        print(render_table(data))
    else:
        print(json.dumps(data, indent=2, default=str))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="depwolf",
        description="Post-process any scanner output (Trivy, Grype, SAST, ...): CVE extraction "
        "-> AVIP FP reduction -> AI remediation",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a project dir (manifests) or post-process scanner report(s)")
    s.add_argument(
        "inputs",
        nargs="*",
        default=["-"],
        help="a project directory to scan (requirements.txt, package.json, go.mod, ...), "
        "scanner report file(s), or '-' for stdin (default: stdin)",
    )
    s.add_argument("--os", choices=["linux", "windows"], default=None)
    s.add_argument("--threshold", type=int, default=60, help="fail gate: risk score >= threshold (default 60)")
    s.add_argument("--no-remediate", action="store_true", help="skip remediation (enabled by default)")
    s.add_argument("--format", choices=["json", "sarif", "table"], default="json")
    s.add_argument("--stack", default=None, help="path to a 'pkg version' stack file for tighter FP reduction")
    s.add_argument("--save", default=None, help="also write the JSON report to this path")

    r = sub.add_parser("remediate", help="remediation for CVE IDs (any scan output can be reduced to CVE IDs)")
    r.add_argument("cves", nargs="+")
    r.add_argument("--threshold", type=int, default=60)
    r.add_argument("--format", choices=["json", "table"], default="table", help="output format (default: table)")

    v = sub.add_parser(
        "verify",
        help=(
            "check whether an installed version still needs remediation for a CVE "
            "(FIXED / STILL VULNERABLE / UNABLE TO VERIFY)"
        ),
    )
    v.add_argument("cves", nargs="+")
    v.add_argument("--version", default=None, help="installed version to check against the CVE's affected ranges")

    sync = sub.add_parser("sync", help="download or refresh cpe_index.db")
    sync.add_argument(
        "--check", action="store_true", help="verify index integrity (manifest/signature/checksum) without rebuilding"
    )
    sync.add_argument(
        "--full", action="store_true", help="force a full rebuild from NVD/EPSS/KEV instead of downloading"
    )

    sub.add_parser("db", help="show index path, verification status, and stats")

    ig = sub.add_parser("ignore", help="persist CVEs to the ignored list")
    ig.add_argument("cves", nargs="+")
    un = sub.add_parser("unignore", help="remove CVEs from the ignored list")
    un.add_argument("cves", nargs="+")

    e = sub.add_parser("export", help="re-render a saved JSON report")
    e.add_argument("file")
    e.add_argument("--format", choices=["json", "sarif", "table"], default="sarif")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return _scan(args.inputs, args.os, args.threshold, not args.no_remediate, args.format, args.save, args.stack)
    if args.command == "remediate":
        return _remediate(args.cves, args.threshold, args.format)
    if args.command == "verify":
        return _verify(args.cves, args.version)
    if args.command == "sync":
        return _sync(check=args.check, full=args.full)
    if args.command == "db":
        return _db_info()
    if args.command == "ignore":
        return _ignore(args.cves, unignore=False)
    if args.command == "unignore":
        return _ignore(args.cves, unignore=True)
    if args.command == "export":
        return _export(Path(args.file), args.format)
    return 2


if __name__ == "__main__":
    sys.exit(main())
