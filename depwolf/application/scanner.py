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
    "site-packages",
    "dist-info",
    "egg-info",
    ".egg-info",
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


def _version_meta(version: str | None, source: str) -> dict:
    """Provenance for a resolved version: EXACT/UNKNOWN + where it came from.

    A version is EXACT only when the manifest/lockfile pins it. Unknown versions
    report ``unavailable`` as their source so consumers never guess.
    """
    return {
        "version_confidence": "EXACT" if version else "UNKNOWN",
        "version_source": source if version else "unavailable",
    }


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
        deps.append(
            {
                "name": name,
                "version": version,
                "ecosystem": "python",
                "artifact": name,
                "direct": True,
                **_version_meta(version, "manifest"),
            }
        )
    return deps


def _npm_split(name: str) -> tuple[str | None, str]:
    """Split an npm package name into (scope, bare-name)."""
    if name.startswith("@"):
        parts = name[1:].split("/", 1)
        if len(parts) == 2:
            return parts[0], parts[1]
    return None, name.rsplit("/", 1)[-1]


def _parse_package_json(path: Path) -> list[dict]:
    deps: list[dict] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return deps
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            group, artifact = _npm_split(str(name))
            version = _clean_version(str(spec))
            deps.append(
                {
                    "name": str(name),
                    "version": version,
                    "ecosystem": "npm",
                    "group": group,
                    "artifact": artifact,
                    "direct": True,
                    **_version_meta(version, "manifest"),
                }
            )
    return deps


def _parse_package_lock(path: Path) -> list[dict]:
    deps: list[dict] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return deps
    seen: set[tuple[str, str | None]] = set()

    def add(name: str, version: str | None, direct: bool | None, chain: tuple[str, ...] | None) -> None:
        version = _clean_version(version)
        key = (name, version)
        if key in seen:
            return
        seen.add(key)
        group, artifact = _npm_split(name)
        d: dict = {
            "name": name,
            "version": version,
            "ecosystem": "npm",
            "group": group,
            "artifact": artifact,
            "direct": direct,
            **_version_meta(version, "lockfile"),
        }
        if chain:
            d["path"] = chain
        deps.append(d)

    deps_map = data.get("dependencies")
    if isinstance(deps_map, dict):

        def walk(items: dict, chain: tuple[str, ...], direct: bool | None) -> None:
            for name, info in items.items():
                info = info if isinstance(info, dict) else {}
                add(str(name), info.get("version"), direct, chain + (str(name),))
                sub = info.get("dependencies")
                if isinstance(sub, dict):
                    walk(sub, chain + (str(name),), False)

        walk(deps_map, (), True)
    pkgs = data.get("packages")
    if isinstance(pkgs, dict):
        for loc, info in pkgs.items():
            if not loc:
                continue
            info = info if isinstance(info, dict) else {}
            name = str(loc)
            chain: tuple[str, ...] | None = None
            direct: bool | None = None
            if name.startswith("node_modules/"):
                rel = name[len("node_modules/") :]
                chain = tuple(rel.split("/node_modules/"))
                direct = len(chain) == 1
                name = chain[-1]
            group, artifact = _npm_split(name)
            d = {
                "name": f"@{group}/{artifact}" if group else artifact,
                "version": _clean_version(info.get("version")),
                "ecosystem": "npm",
                "group": group,
                "artifact": artifact,
                "direct": direct,
                **_version_meta(_clean_version(info.get("version")), "lockfile"),
            }
            if chain:
                d["path"] = chain
            deps.append(d)
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
                group, artifact = _npm_split(name)
                version = _clean_version(m.group(1))
                deps.append(
                    {
                        "name": name,
                        "version": version,
                        "ecosystem": "npm",
                        "group": group,
                        "artifact": artifact,
                        "direct": None,
                        **_version_meta(version, "lockfile"),
                    }
                )
            name = None
    return deps


def _parse_go_mod(path: Path) -> list[dict]:
    deps: list[dict] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return deps
    for line in text.splitlines():
        indirect = "// indirect" in line
        line = line.split("//")[0].strip()
        m = re.match(r"^([^\s]+)\s+(v[0-9][0-9a-zA-Z.+\-]*)$", line)
        if not m or m.group(1) in ("go", "toolchain"):
            continue
        module = m.group(1)
        name = module.rsplit("/", 1)[-1]
        deps.append(
            {
                "name": name,
                "version": m.group(2),
                "ecosystem": "go",
                "group": module,
                "artifact": name,
                "direct": not indirect,
                **_version_meta(m.group(2), "manifest"),
            }
        )
    return deps


def _pom_properties(text: str) -> dict[str, str]:
    """Resolve Maven <properties> blocks into a {name: value} map."""
    props: dict[str, str] = {}
    m = re.search(r"<properties>(.*?)</properties>", text, re.S)
    if m:
        for pm in re.finditer(r"<([a-zA-Z0-9._-]+)>(.*?)</\1>", m.group(1), re.S):
            props[pm.group(1)] = pm.group(2).strip()
    return props


def _parse_pom(path: Path) -> list[dict]:
    deps: list[dict] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return deps
    props = _pom_properties(text)
    for block in re.findall(r"<dependency>(.*?)</dependency>", text, re.S):
        g = re.search(r"<groupId>(.*?)</groupId>", block, re.S)
        a = re.search(r"<artifactId>(.*?)</artifactId>", block, re.S)
        v = re.search(r"<version>(.*?)</version>", block, re.S)
        if not a:
            continue
        group = g.group(1).strip() if g else ""
        artifact = a.group(1).strip()
        raw = v.group(1).strip() if v else ""
        version = None
        if raw:
            prop = re.fullmatch(r"\$\{([^}]+)\}", raw)
            if prop:
                version = _clean_version(props.get(prop.group(1), "")) if prop.group(1) in props else None
            else:
                version = _clean_version(raw)
        deps.append(
            {
                "name": f"{group}:{artifact}" if group else artifact,
                "version": version,
                "ecosystem": "java",
                "group": group,
                "artifact": artifact,
                "direct": True,
                **_version_meta(version, "manifest"),
            }
        )
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
        version = _clean_version(m.group(2))
        deps.append(
            {
                "name": m.group(1),
                "version": version,
                "ecosystem": "ruby",
                "artifact": m.group(1),
                "direct": True,
                **_version_meta(version, "lockfile"),
            }
        )
    return deps


def _parse_cargo_lock(path: Path) -> list[dict]:
    deps: list[dict] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return deps
    packages: list[dict] = []
    current: dict | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "[[package]]":
            if current and current.get("name") and current.get("version"):
                packages.append(current)
            current = {"dependencies": []}
            continue
        if current is None:
            continue
        m = re.match(r'^name\s*=\s*"([^"]+)"', stripped)
        if m:
            current["name"] = m.group(1)
            continue
        m = re.match(r'^version\s*=\s*"([^"]+)"', stripped)
        if m:
            current["version"] = _clean_version(m.group(1))
            continue
        if stripped == "dependencies = [" or (current.get("in_deps") and stripped == ","):
            current["in_deps"] = True
            continue
        if stripped.startswith("dependencies = ["):
            current["in_deps"] = True
            inline = re.findall(r'"([^"]+)"', stripped)
            if inline:
                current["dependencies"].extend(inline)
                current["in_deps"] = False
            continue
        if current.get("in_deps"):
            m = re.match(r'^"([^"]+)"', stripped)
            if m:
                current["dependencies"].append(m.group(1))
                continue
            if stripped.startswith("]"):
                current["in_deps"] = False
                continue
    if current and current.get("name") and current.get("version"):
        packages.append(current)

    depended_on = {dep for p in packages for dep in p.get("dependencies", [])}
    roots = [p["name"] for p in packages if p["name"] not in depended_on]
    index: dict[str, dict] = {p["name"]: p for p in packages}

    def find_path(target: str) -> tuple[str, ...] | None:
        for root in roots:
            seen: set[str] = set()
            stack: list[tuple[str, tuple[str, ...]]] = [(root, (root,))]
            while stack:
                node, chain = stack.pop()
                if node == target:
                    return chain
                if node in seen:
                    continue
                seen.add(node)
                for dep in index.get(node, {}).get("dependencies", []):
                    if dep not in chain:
                        stack.append((dep, chain + (dep,)))
        return None

    for p in packages:
        direct = p["name"] in roots
        dep_path = (p["name"],) if direct else find_path(p["name"])
        deps.append(
            {
                "name": p["name"],
                "version": p["version"],
                "ecosystem": "rust",
                "artifact": p["name"],
                "direct": direct,
                "path": dep_path,
                **_version_meta(p["version"], "lockfile"),
            }
        )
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
            deps.append(
                {
                    "name": name,
                    "version": version,
                    "ecosystem": "python",
                    "artifact": name,
                    **_version_meta(version, "lockfile"),
                }
            )
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
        version = _clean_version(pkg.get("version"))
        deps.append(
            {
                "name": name,
                "version": version,
                "ecosystem": "php",
                "artifact": name,
                "direct": None,
                **_version_meta(version, "lockfile"),
            }
        )
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
        version = ver if op == "==" else None
        deps.append(
            {
                "name": name,
                "version": version,
                "ecosystem": "python",
                "artifact": name,
                "direct": True,
                **_version_meta(version, "manifest"),
            }
        )
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
    from depwolf.application.matcher import match_plan_full

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
            "plan_conf": {},
        }
    plan, plan_conf = match_plan_full(stack, store=store)
    return {
        "manifests": [str(m) for m in manifests],
        "deps": deps,
        "stack": stack,
        "cve_ids": list(plan),
        "plan": plan,
        "plan_conf": plan_conf,
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
    result = prioritize_cves(
        collected["cve_ids"],
        collected["stack"],
        store=store,
        plan=collected["plan"],
        plan_conf=collected["plan_conf"],
    )
    result["source"] = "manifest-scan"
    result["manifests"] = collected["manifests"]
    result["deps"] = collected["deps"]
    result["stack"] = collected["stack"]
    return result
