"""Typed scanner adapters (Phase 4, pulled forward).

Every supported scanner has a dedicated adapter that emits typed
``CVEReference`` objects (with ``source`` and ``confidence``) instead of the
old regex-heuristic dicts. The heuristic remains as a low-confidence fallback
(confidence 0.3) for anything the adapters don't recognize.
"""

from __future__ import annotations

import re
from typing import Any, Protocol

from depwolf.domain.model import CVEReference

CVE_RE = re.compile(r"(?i)\b(CVE-\d{4}-\d{4,7})\b")


def _is_cve(s: str) -> bool:
    return bool(s and isinstance(s, str) and CVE_RE.fullmatch(s.strip()))


def _cve_ids_in(text: str | None) -> list[str]:
    return [m.group(1).upper() for m in CVE_RE.finditer(text or "")]


class ScannerAdapter(Protocol):
    """A per-scanner parser producing typed references."""

    name: str

    def supports(self, data: Any) -> bool: ...
    def extract(self, data: Any) -> list[CVEReference]: ...


class TrivyAdapter:
    name = "trivy"

    def supports(self, data: Any) -> bool:
        return (
            isinstance(data, dict)
            and isinstance(data.get("Results"), list)
            and any("Vulnerabilities" in r for r in data["Results"] if isinstance(r, dict))
        )

    def extract(self, data: dict) -> list[CVEReference]:
        refs: list[CVEReference] = []
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                cve_id = (vuln.get("VulnerabilityID") or "").strip().upper()
                if not _is_cve(cve_id):
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
        return refs


class GrypeAdapter:
    name = "grype"

    def supports(self, data: Any) -> bool:
        return isinstance(data, dict) and isinstance(data.get("matches"), list)

    def extract(self, data: dict) -> list[CVEReference]:
        refs: list[CVEReference] = []
        target = (data.get("source") or {}).get("target")
        for match in data.get("matches", []):
            vuln = match.get("vulnerability") or {}
            cve_id = (vuln.get("id") or "").strip().upper()
            if not _is_cve(cve_id):
                continue
            artifact = match.get("artifact") or {}
            fix = vuln.get("fix") or {}
            versions = fix.get("versions") if isinstance(fix, dict) else None
            refs.append(
                CVEReference(
                    cve_id=cve_id,
                    pkg=artifact.get("name"),
                    installed_version=artifact.get("version"),
                    fixed_version=versions[0] if versions else None,
                    severity=vuln.get("severity"),
                    target=target,
                    source="grype",
                )
            )
        return refs


class SnykAdapter:
    name = "snyk"

    def supports(self, data: Any) -> bool:
        if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
            return False
        vulns = data["vulnerabilities"]
        if not vulns or not isinstance(vulns[0], dict):
            return False
        return any(
            v.get("packageName") or v.get("identifiers") or str(v.get("id", "")).startswith("SNYK-") for v in vulns
        )

    def extract(self, data: dict) -> list[CVEReference]:
        refs: list[CVEReference] = []
        target = data.get("displayTargetFile")
        for vuln in data.get("vulnerabilities", []):
            ids = [str(i).upper() for i in (vuln.get("identifiers") or {}).get("CVE", [])]
            if not ids and _is_cve(str(vuln.get("id", ""))):
                ids = [str(vuln["id"]).upper()]
            pkg_obj = vuln.get("package") if isinstance(vuln.get("package"), dict) else {}
            pkg = vuln.get("packageName") or pkg_obj.get("name")
            version = vuln.get("version") or pkg_obj.get("version")
            for cve in dict.fromkeys(ids):
                refs.append(
                    CVEReference(
                        cve_id=cve,
                        pkg=pkg,
                        installed_version=version,
                        severity=vuln.get("severity"),
                        target=target,
                        source="snyk",
                    )
                )
        return refs


class DependencyCheckAdapter:
    name = "dependency-check"

    def supports(self, data: Any) -> bool:
        return (
            isinstance(data, dict)
            and isinstance(data.get("dependencies"), list)
            and isinstance(data.get("vulnerabilities"), list)
        )

    def extract(self, data: dict) -> list[CVEReference]:
        severity_by_cve: dict[str, str] = {}
        for v in data.get("vulnerabilities", []):
            name = (v.get("name") or "").strip().upper()
            if _is_cve(name):
                severity_by_cve[name] = v.get("severity")
        refs: list[CVEReference] = []
        for dep in data.get("dependencies", []):
            cves = [
                str(v.get("id", "")).strip().upper()
                for v in dep.get("vulnerabilityIds") or []
                if _is_cve(str(v.get("id", "")))
            ]
            if not cves:
                continue
            pkg = None
            packages = dep.get("packages") or []
            if packages:
                pid = packages[0].get("id") or packages[0].get("path") or ""
                pkg = pid.rsplit("/", 1)[-1] or None
            for cve in dict.fromkeys(cves):
                refs.append(
                    CVEReference(
                        cve_id=cve,
                        pkg=pkg,
                        severity=severity_by_cve.get(cve),
                        target=dep.get("filePath") or dep.get("fileName"),
                        source="dependency-check",
                    )
                )
        return refs


class SarifAdapter:
    """Generic SARIF 2.1.0 (also handles CodeQL and Semgrep SARIF)."""

    name = "sarif"

    def supports(self, data: Any) -> bool:
        return (
            isinstance(data, dict)
            and isinstance(data.get("runs"), list)
            and (data.get("version") == "2.1.0" or "sarif" in str(data.get("$schema", "")).lower())
        )

    def extract(self, data: dict, source: str | None = None) -> list[CVEReference]:
        return _extract_sarif(data, source=source)


def _extract_sarif(data: dict, source: str | None = None) -> list[CVEReference]:
    refs: list[CVEReference] = []
    for run in data.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        name = driver.get("name") or "sarif"
        for result in run.get("results", []):
            rule_id = result.get("ruleId") or ""
            ids = [i for i in _cve_ids_in(rule_id) if _is_cve(i)]
            if not ids:
                ids = [
                    i
                    for i in _cve_ids_in(
                        str(result.get("message", {}).get("text", "")) + str(result.get("properties", {}))
                    )
                    if _is_cve(i)
                ]
            if not ids:
                continue
            uri = None
            locations = result.get("locations") or []
            if locations:
                art = locations[0].get("physicalLocation", {}).get("artifactLocation", {})
                uri = art.get("uri") or art.get("uriBaseId")
            for cve in dict.fromkeys(ids):
                refs.append(
                    CVEReference(
                        cve_id=cve,
                        target=uri,
                        severity=None,
                        source=source or (name or "sarif"),
                    )
                )
    return refs


class CodeQLAdapter:
    name = "codeql"

    def supports(self, data: Any) -> bool:
        if not SarifAdapter().supports(data):
            return False
        for run in data.get("runs", []):
            name = str(run.get("tool", {}).get("driver", {}).get("name", "")).lower()
            if "codeql" in name or "code-scanning" in name:
                return True
        return False

    def extract(self, data: dict) -> list[CVEReference]:
        return _extract_sarif(data, source="codeql")


class SemgrepAdapter:
    """Semgrep JSON output, or Semgrep SARIF (driver name)."""

    name = "semgrep"

    def supports(self, data: Any) -> bool:
        if isinstance(data, dict) and isinstance(data.get("results"), list):
            first = data["results"][0] if data["results"] else {}
            if isinstance(first, dict) and ("check_id" in first or "path" in first):
                return True
        if not SarifAdapter().supports(data):
            return False
        for run in data.get("runs", []):
            if str(run.get("tool", {}).get("driver", {}).get("name", "")).lower() == "semgrep":
                return True
        return False

    def extract(self, data: dict) -> list[CVEReference]:
        if SarifAdapter().supports(data):
            return _extract_sarif(data, source="semgrep")
        refs: list[CVEReference] = []
        for result in data.get("results", []):
            extra = result.get("extra") or {}
            metadata = extra.get("metadata") or {}
            haystack = str(result.get("check_id", "")) + " " + " ".join(str(v) for v in metadata.values())
            ids = [i for i in _cve_ids_in(haystack) if _is_cve(i)]
            if not ids:
                continue
            severity = extra.get("severity")
            for cve in dict.fromkeys(ids):
                refs.append(
                    CVEReference(
                        cve_id=cve,
                        target=result.get("path"),
                        severity=severity,
                        source="semgrep",
                        confidence=0.9,
                    )
                )
        return refs


class HeuristicAdapter:
    """Last-resort pattern extraction for unrecognized JSON structures."""

    name = "heuristic"

    def supports(self, data: Any) -> bool:
        return isinstance(data, (dict, list))

    def extract(self, data: Any) -> list[CVEReference]:
        sink: list[CVEReference] = []
        _heuristic_walk(data, sink)
        return sink


_PKG_KEYS = ("pkgname", "package", "pkg", "artifact", "component", "library", "product")
_VERSION_KEYS = ("installedversion", "affectedversion", "currentversion", "version", "affectedversionrange")
_FIXED_KEYS = ("fixedversion", "fixversion", "fixed_version")
_SEV_KEYS = ("severity", "criticality", "level", "score")
_TARGET_KEYS = ("target", "file", "path", "artifactlocation", "uri", "location")


def _norm_key(k: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (k or "").lower())


def _first(d: dict, keys) -> Any | None:
    if not d:
        return None
    wanted = {_norm_key(k) for k in keys}
    for k, v in d.items():
        if _norm_key(k) in wanted and v not in (None, "", [], {}) and not isinstance(v, (dict, list)):
            return v
    return None


def _heuristic_walk(d: Any, sink: list[CVEReference], parent: dict | None = None) -> None:
    if isinstance(d, dict):
        cve_id = next(
            (v.strip().upper() for k, v in d.items() if isinstance(v, str) and _is_cve(v)),
            None,
        )
        if cve_id:
            ctx = parent or d
            sink.append(
                CVEReference(
                    cve_id=cve_id,
                    pkg=_first(d, _PKG_KEYS) or _first(ctx, _PKG_KEYS),
                    installed_version=_first(d, _VERSION_KEYS) or _first(ctx, _VERSION_KEYS),
                    fixed_version=_first(d, _FIXED_KEYS) or _first(ctx, _FIXED_KEYS),
                    severity=_first(d, _SEV_KEYS) or _first(ctx, _SEV_KEYS),
                    target=_first(d, _TARGET_KEYS) or _first(ctx, _TARGET_KEYS),
                    source="heuristic",
                    confidence=0.3,
                )
            )
        for _k, v in d.items():
            if isinstance(v, (dict, list)):
                _heuristic_walk(v, sink, d)
    elif isinstance(d, list):
        for item in d:
            if isinstance(item, (dict, list)):
                _heuristic_walk(item, sink, parent)
            elif isinstance(item, str):
                ids = [i for i in _cve_ids_in(item) if _is_cve(i)]
                for cve in ids:
                    sink.append(
                        CVEReference(
                            cve_id=cve,
                            pkg=_first(parent, _PKG_KEYS) if parent else None,
                            installed_version=_first(parent, _VERSION_KEYS) if parent else None,
                            source="heuristic",
                            confidence=0.3,
                        )
                    )


def extract_cves_typed(data: Any) -> list[CVEReference]:
    """Dispatch scanner output to the right typed adapter (or the fallback)."""
    adapters: list[ScannerAdapter] = [
        TrivyAdapter(),
        GrypeAdapter(),
        SnykAdapter(),
        DependencyCheckAdapter(),
        SemgrepAdapter(),
        CodeQLAdapter(),
        SarifAdapter(),
        HeuristicAdapter(),
    ]
    for adapter in adapters:
        try:
            if adapter.supports(data):
                return adapter.extract(data)
        except Exception:
            continue
    return []
