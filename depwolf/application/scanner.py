"""Native project scanner: discover dependency manifests and resolve CVEs directly.

Lets `depwolf scan <dir>` behave like a real scanner: instead of requiring an
external report (Trivy/Grype/SAST), it walks a project, parses its dependency
manifests, resolves each pinned package against the CVE index, and runs the
same AVIP false-positive funnel + risk + remediation pipeline.
"""

import json
import logging
import re
from collections.abc import Callable
from pathlib import Path

from depwolf.domain.ports import CVERepository

logger = logging.getLogger(__name__)

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
    "vendor",
}

_MANIFEST_PARSERS: dict[str, Callable] = {}


def _clean_version(v: str | None) -> str | None:
    """Best-effort normalize a manifest version spec to a bare installed version."""
    if not v:
        return None
    v = v.strip().strip("\"'")
    if not v or v.lower() in ("latest", "any"):
        return None
    v = re.sub(r"^[vV]", "", v)
    v = re.sub(r"^==\s*", "", v)
    if re.match(r"^[\^~<>=!*]|[,\s]|^[^0-9]", v):
        return None
    return v or None


def _parse_requirements(path: Path) -> list[dict]:
    deps: list[dict] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return deps
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith(("-", ".")) or "://" in line:
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?(.*)$", line)
        if not m:
            continue
        name = m.group(1)
        spec = m.group(2).strip()
        version = None
        eq = re.match(r"^==\s*([0-9][0-9a-zA-Z.+\-]*)", spec)
        if eq:
            version = eq.group(1)
        deps.append({"name": name, "version": version, "ecosystem": "python"})
    return deps


def _parse_package_json(path: Path) -> list[dict]:
    deps: list[dict] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return deps
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            deps.append({"name": name, "version": _clean_version(str(spec)), "ecosystem": "npm"})
    return deps


def _parse_package_lock(path: Path) -> list[dict]:
    deps: list[dict] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return deps
    seen = set()
    for name, info in (data.get("dependencies") or {}).items():
        version = _clean_version(info.get("version") if isinstance(info, dict) else str(info))
        if name not in seen:
            seen.add(name)
            deps.append({"name": name, "version": version, "ecosystem": "npm"})
    return deps


def _parse_yarn_lock(path: Path) -> list[dict]:
    deps: list[dict] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return deps
    name = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('"') or re.match(r"^[A-Za-z0-9_@./\-]+@", stripped):
            m = re.match(r"^\"?([^\"@/]+)@", stripped)
            if m:
                name = m.group(1)
            continue
        if name and stripped.startswith("version"):
            m = re.match(r'^version\s+"?([^"\s]+)', stripped)
            if m:
                deps.append({"name": name, "version": _clean_version(m.group(1)), "ecosystem": "npm"})
            name = None
    return deps


def _parse_go_mod(path: Path) -> list[dict]:
    deps: list[dict] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return deps
    for line in text.splitlines():
        line = line.split("//")[0].strip()
        m = re.match(r"^([^\s]+)\s+(v[0-9][0-9a-zA-Z.+\-]*)$", line)
        if not m or m.group(1) in ("go", "toolchain"):
            continue
        name = m.group(1)
        if "/" in name:
            name = name.rsplit("/", 1)[-1]
        deps.append({"name": name, "version": m.group(2), "ecosystem": "go"})
    return deps


def _parse_pom(path: Path) -> list[dict]:
    deps: list[dict] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return deps
    for block in re.findall(r"<dependency>(.*?)</dependency>", text, re.S):
        g = re.search(r"<groupId>(.*?)</groupId>", block, re.S)
        a = re.search(r"<artifactId>(.*?)</artifactId>", block, re.S)
        v = re.search(r"<version>(.*?)</version>", block, re.S)
        if not a:
            continue
        group = g.group(1).strip() if g else ""
        artifact = a.group(1).strip()
        version = _clean_version(v.group(1).strip()) if v else None
        if version and v is not None and "${" in v.group(1):
            version = None
        deps.append({"name": f"{group}:{artifact}" if group else artifact, "version": version, "ecosystem": "java"})
    return deps


def _parse_gemfile_lock(path: Path) -> list[dict]:
    deps: list[dict] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return deps
    for line in text.splitlines():
        m = re.match(r"^\s{4}(\S+)\s+\(([^)]+)\)", line)
        if not m:
            continue
        deps.append({"name": m.group(1), "version": _clean_version(m.group(2)), "ecosystem": "ruby"})
    return deps


def _parse_cargo_lock(path: Path) -> list[dict]:
    deps: list[dict] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return deps
    name = version = None
    for line in text.splitlines():
        if line.strip() == "[[package]]":
            if name and version:
                deps.append({"name": name, "version": version, "ecosystem": "rust"})
            name = version = None
            continue
        m = re.match(r'^\s*name\s*=\s*"([^"]+)"', line)
        if m:
            name = m.group(1)
            continue
        m = re.match(r'^\s*version\s*=\s*"([^"]+)"', line)
        if m:
            version = _clean_version(m.group(1))
    if name and version:
        deps.append({"name": name, "version": version, "ecosystem": "rust"})
    return deps


def _parse_pipfile_lock(path: Path) -> list[dict]:
    deps: list[dict] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return deps
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            version = _clean_version(info.get("version")) if isinstance(info, dict) else None
            deps.append({"name": name, "version": version, "ecosystem": "python"})
    return deps


def _parse_composer_lock(path: Path) -> list[dict]:
    deps: list[dict] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return deps
    for pkg in data.get("packages") or []:
        name = (pkg.get("name") or "").split("/")[-1]
        if not name:
            continue
        deps.append({"name": name, "version": _clean_version(pkg.get("version")), "ecosystem": "php"})
    return deps


def _parse_pyproject(path: Path) -> list[dict]:
    deps: list[dict] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return deps
    pattern = (
        r'["\']([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|!=|===)\s*["\']?'
        r"\s*([0-9][0-9a-zA-Z.+\-]*)[\"']?"
    )
    for m in re.finditer(pattern, text):
        name, op, ver = m.group(1), m.group(2), m.group(3)
        deps.append({"name": name, "version": ver if op == "==" else None, "ecosystem": "python"})
    return deps


_MANIFEST_PARSERS = {
    "requirements.txt": _parse_requirements,
    "requirements-dev.txt": _parse_requirements,
    "package.json": _parse_package_json,
    "package-lock.json": _parse_package_lock,
    "npm-shrinkwrap.json": _parse_package_lock,
    "yarn.lock": _parse_yarn_lock,
    "go.mod": _parse_go_mod,
    "pom.xml": _parse_pom,
    "Gemfile.lock": _parse_gemfile_lock,
    "Cargo.lock": _parse_cargo_lock,
    "Pipfile.lock": _parse_pipfile_lock,
    "poetry.lock": _parse_pipfile_lock,
    "composer.lock": _parse_composer_lock,
    "pyproject.toml": _parse_pyproject,
}


def find_manifests(root: Path) -> list[Path]:
    """Recursively find dependency manifests under root, skipping vendored dirs."""
    if not root.exists():
        return []
    found = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if p.name in _MANIFEST_PARSERS:
            found.append(p)
    return found


def parse_manifests(manifests: list[Path]) -> list[dict]:
    deps: list[dict] = []
    for path in manifests:
        parser = _MANIFEST_PARSERS.get(path.name)
        if not parser:
            continue
        try:
            for d in parser(path):
                d["manifest"] = str(path)
                deps.append(d)
        except Exception as e:
            logger.warning(f"could not parse manifest {path}: {e}")
    return deps


def deps_to_stack(deps: list[dict]) -> str:
    """Build the 'name version' stack lines used by the FP funnel."""
    lines = []
    for d in deps:
        name = d.get("name")
        if not name:
            continue
        if ":" in name:
            name = name.split(":", 1)[-1]
        if d.get("version"):
            lines.append(f"{name} {d['version']}")
        else:
            lines.append(name)
    return "\n".join(dict.fromkeys(lines))


def collect_project(root: Path, store: CVERepository | None = None) -> dict:
    """Discover manifests and resolve the CVE candidates they map to (no funnel)."""
    from depwolf.application.matcher import match_plan

    manifests = find_manifests(root)
    deps = parse_manifests(manifests)
    stack = deps_to_stack(deps)
    if not stack:
        return {
            "error": f"No supported dependency manifests found under {root}",
            "manifests": [],
            "deps": [],
            "stack": "",
            "cve_ids": [],
        }
    plan = match_plan(stack, store=store)
    return {
        "manifests": [str(m) for m in manifests],
        "deps": deps,
        "stack": stack,
        "cve_ids": list(plan),
        "plan": plan,
    }


def scan_project(root: Path, store: CVERepository | None = None) -> dict:
    """Native scan: manifests -> CVE candidates -> prioritized findings.

    Resolves the candidate plan once (2 repository calls) and reuses it in the
    funnel, so a native scan touches the DB exactly once per scan.
    """
    from depwolf.application.matcher import prioritize_cves

    collected = collect_project(root, store=store)
    if collected.get("error"):
        return {
            "error": collected["error"],
            "prioritized": [],
            "filtered_details": [],
            "manifests": [],
            "deps": [],
            "stack": "",
        }
    result = prioritize_cves(collected["cve_ids"], collected["stack"], store=store, plan=collected["plan"])
    result["source"] = "manifest-scan"
    result["manifests"] = collected["manifests"]
    result["deps"] = collected["deps"]
    result["stack"] = collected["stack"]
    return result
