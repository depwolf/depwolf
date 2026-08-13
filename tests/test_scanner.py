import json
from pathlib import Path

from depwolf.scanner import (
    collect_project,
    deps_to_stack,
    find_manifests,
    parse_manifests,
    scan_project,
)

REQ = """flask==0.12.3
requests>=2.19.1
# comment
-e .
urllib3==1.25.11
"""

PKG_JSON = json.dumps(
    {
        "name": "demo",
        "dependencies": {"lodash": "^4.17.21", "axios": "0.21.1"},
        "devDependencies": {"webpack": "5.0.0"},
    }
)

LOCK = json.dumps({"name": "demo", "dependencies": {"express": {"version": "4.17.1"}}})

GO = """module github.com/example/app

go 1.21

require (
\tgithub.com/gin-gonic/gin v1.7.4
\tgolang.org/x/net v0.0.0-20210226172049-e18ecbb05110 // indirect
)
"""

POM = """<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>skipped</artifactId>
      <version>${revision}</version>
    </dependency>
  </dependencies>
</project>
"""

GEM = """GEM
  specs:
    rails (6.1.4)
    rack (~> 2.2, >= 2.2.4)
"""

CARGO = """[[package]]
name = "serde"
version = "1.0.130"

[[package]]
name = "log"
version = "0.4.14"
"""


def _write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def test_find_manifests_recursive(tmp_path):
    _write(tmp_path, "requirements.txt", REQ)
    _write(tmp_path, "sub/package.json", PKG_JSON)
    _write(tmp_path, "vendor/go.mod", GO)
    found = {p.relative_to(tmp_path).as_posix() for p in find_manifests(tmp_path)}
    assert "requirements.txt" in found
    assert "sub/package.json" in found
    assert "vendor/go.mod" not in found


def test_requirements_parser(tmp_path):
    p = _write(tmp_path, "requirements.txt", REQ)
    deps = parse_manifests([p])
    by_name = {d["name"]: d for d in deps}
    assert by_name["flask"]["version"] == "0.12.3"
    assert by_name["urllib3"]["version"] == "1.25.11"
    assert by_name["requests"]["version"] is None


def test_package_json_and_lock(tmp_path):
    p1 = _write(tmp_path, "package.json", PKG_JSON)
    p2 = _write(tmp_path, "package-lock.json", LOCK)
    deps = parse_manifests([p1, p2])
    by_name = {d["name"]: d for d in deps}
    assert by_name["axios"]["version"] == "0.21.1"
    assert by_name["lodash"]["version"] is None
    assert by_name["express"]["version"] == "4.17.1"


def test_go_mod(tmp_path):
    p = _write(tmp_path, "go.mod", GO)
    deps = parse_manifests([p])
    by_name = {d["name"]: d for d in deps}
    assert by_name["gin"]["version"] == "v1.7.4"
    assert by_name["net"]["version"].startswith("v0")


def test_pom(tmp_path):
    p = _write(tmp_path, "pom.xml", POM)
    deps = parse_manifests([p])
    by_name = {d["name"]: d for d in deps}
    assert by_name["org.apache.logging.log4j:log4j-core"]["version"] == "2.14.1"
    assert by_name["org.apache.logging.log4j:log4j-core"]["version_confidence"] == "EXACT"
    assert by_name["org.apache.logging.log4j:log4j-core"]["version_source"] == "manifest"
    assert by_name["com.example:skipped"]["version"] is None
    assert by_name["com.example:skipped"]["version_confidence"] == "UNKNOWN"
    assert by_name["com.example:skipped"]["version_source"] == "unavailable"


def test_pom_property_resolution(tmp_path):
    pom = """<project>
  <properties>
    <log4j.version>2.14.1</log4j.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>${log4j.version}</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>unresolved</artifactId>
      <version>${missing.version}</version>
    </dependency>
  </dependencies>
</project>
"""
    p = _write(tmp_path, "pom.xml", pom)
    deps = parse_manifests([p])
    by_name = {d["name"]: d for d in deps}
    assert by_name["org.apache.logging.log4j:log4j-core"]["version"] == "2.14.1"
    assert by_name["org.apache.logging.log4j:log4j-core"]["version_confidence"] == "EXACT"
    assert by_name["org.apache.logging.log4j:log4j-core"]["version_source"] == "manifest"
    assert by_name["com.example:unresolved"]["version"] is None
    assert by_name["com.example:unresolved"]["version_confidence"] == "UNKNOWN"


def test_gemfile_and_cargo(tmp_path):
    g = _write(tmp_path, "Gemfile.lock", GEM)
    c = _write(tmp_path, "Cargo.lock", CARGO)
    gem = {d["name"]: d for d in parse_manifests([g])}
    assert gem["rails"]["version"] == "6.1.4"
    cargo = {d["name"]: d for d in parse_manifests([c])}
    assert cargo["serde"]["version"] == "1.0.130"


def test_deps_to_stack_lines():
    deps = [
        {"name": "flask", "version": "0.12.3"},
        {"name": "requests", "version": None},
        {"name": "org.group:artifact", "version": "1.0.0"},
    ]
    stack = deps_to_stack(deps)
    lines = stack.splitlines()
    assert "flask 0.12.3" in lines
    assert "requests" in lines
    assert "artifact 1.0.0" in lines


def test_collect_project_no_manifests(tmp_path):
    (tmp_path / "readme.txt").write_text("no manifests here", encoding="utf-8")
    result = collect_project(tmp_path)
    assert result.get("error")
    assert result["cve_ids"] == []


def test_collect_project_candidates(tmp_path, index_store):
    _write(tmp_path, "pom.xml", POM)
    result = collect_project(tmp_path, store=index_store)
    assert not result.get("error")
    assert result["stack"]
    assert "log4j-core 2.14.1" in result["stack"]


def test_pom_group_artifact_ecosystem(tmp_path):
    p = _write(tmp_path, "pom.xml", POM)
    deps = parse_manifests([p])
    by_name = {d["name"]: d for d in deps}
    dep = by_name["org.apache.logging.log4j:log4j-core"]
    assert dep["group"] == "org.apache.logging.log4j"
    assert dep["artifact"] == "log4j-core"
    assert dep["ecosystem"] == "java"
    assert dep["direct"] is True


def test_go_mod_direct_and_indirect(tmp_path):
    p = _write(tmp_path, "go.mod", GO)
    deps = parse_manifests([p])
    by_name = {d["name"]: d for d in deps}
    assert by_name["gin"]["direct"] is True
    assert by_name["gin"]["group"] == "github.com/gin-gonic/gin"
    assert by_name["net"]["direct"] is False


def test_npm_scoped_group_and_artifact(tmp_path):
    pkg = json.dumps({"name": "demo", "dependencies": {"@angular/core": "12.0.0"}})
    p = _write(tmp_path, "package.json", pkg)
    deps = parse_manifests([p])
    dep = deps[0]
    assert dep["group"] == "angular"
    assert dep["artifact"] == "core"
    assert dep["direct"] is True


def test_package_lock_nested_is_transitive(tmp_path):
    lock = json.dumps(
        {
            "name": "demo",
            "dependencies": {
                "express": {
                    "version": "4.17.1",
                    "dependencies": {"body-parser": {"version": "1.19.0"}},
                }
            },
        }
    )
    p = _write(tmp_path, "package-lock.json", lock)
    deps = parse_manifests([p])
    by_name = {d["name"]: d for d in deps}
    assert by_name["express"]["direct"] is True
    assert by_name["express"]["version_confidence"] == "EXACT"
    assert by_name["express"]["version_source"] == "lockfile"
    assert by_name["body-parser"]["direct"] is False
    assert by_name["body-parser"]["path"] == ("express", "body-parser")
    assert by_name["body-parser"]["version_confidence"] == "EXACT"
    assert by_name["body-parser"]["version_source"] == "lockfile"


def test_package_lock_v2_node_modules_paths(tmp_path):
    lock = json.dumps(
        {
            "name": "demo",
            "lockfileVersion": 2,
            "packages": {
                "": {"name": "demo", "version": "1.0.0"},
                "node_modules/express": {"version": "4.17.1"},
                "node_modules/express/node_modules/body-parser": {"version": "1.19.0"},
            },
        }
    )
    p = _write(tmp_path, "package-lock.json", lock)
    deps = parse_manifests([p])
    by_name = {d["name"]: d for d in deps}
    assert by_name["express"]["direct"] is True
    assert by_name["express"]["path"] == ("express",)
    assert by_name["body-parser"]["direct"] is False
    assert by_name["body-parser"]["path"] == ("express", "body-parser")
    assert by_name["express"]["version_confidence"] == "EXACT"
    assert by_name["express"]["version_source"] == "lockfile"


def test_cargo_lock_transitive_path(tmp_path):
    cargo = """[[package]]
name = "root"
version = "1.0.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.130"
"""
    p = _write(tmp_path, "Cargo.lock", cargo)
    deps = parse_manifests([p])
    by_name = {d["name"]: d for d in deps}
    assert by_name["root"]["direct"] is True
    assert by_name["serde"]["direct"] is False
    assert by_name["serde"]["path"] == ("root", "serde")


def test_scan_project_finds_log4j_in_memory(tmp_path, memory_index_store):
    _write(tmp_path, "pom.xml", POM)
    result = scan_project(tmp_path, store=memory_index_store)
    assert not result.get("error")
    ids = {f["cve_id"] for f in result["prioritized"]}
    assert "CVE-2021-44228" in ids


def test_scan_project_empty_dir_no_db(tmp_path):
    (tmp_path / "main.py").write_text("x = 1", encoding="utf-8")
    result = scan_project(tmp_path)
    assert result.get("error")
