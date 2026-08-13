from depwolf.application.remediation import _ai_narrative, verify_fix
from depwolf.remediation import generate_remediation

FAKE_NARRATIVE = {
    "executive_summary": "AI narrative summary",
    "root_cause": "AI narrative root cause",
    "step_by_step_fix": ["AI step 1", "AI step 2"],
    "verification": "AI verification steps",
}


def test_ai_remediation_narrative_used(monkeypatch, index_store):
    monkeypatch.setattr(
        "depwolf.application.remediation._ai_narrative",
        lambda cve_id, facts, context: dict(FAKE_NARRATIVE),
    )
    # Confirmed-affected context: AI narrative is only used when the installed
    # version is known and in-range (YES). Unknown applicability must keep the
    # deterministic verification narrative instead.
    rem = generate_remediation(
        "CVE-2021-44228",
        store=index_store,
        context={"installed_version": "2.14.1", "ecosystem": "java", "artifact": "log4j-core", "direct": True},
    )
    assert rem["remediation_source"] == "ai"
    assert rem["executive_summary"] == FAKE_NARRATIVE["executive_summary"]
    assert rem["root_cause"] == FAKE_NARRATIVE["root_cause"]
    assert rem["step_by_step_fix"] == FAKE_NARRATIVE["step_by_step_fix"]
    assert rem["verification"] == FAKE_NARRATIVE["verification"]
    assert rem["fixed_version"] == "2.15.0"
    assert rem["patch_commands"], "patch commands stay DB-grounded"
    assert "log4j-core" in rem["patch_commands"][0]


def test_ai_narrative_not_used_for_unknown_applicability(monkeypatch, index_store):
    monkeypatch.setattr(
        "depwolf.application.remediation._ai_narrative",
        lambda cve_id, facts, context: dict(FAKE_NARRATIVE),
    )
    # No installed version -> UNKNOWN -> the deterministic verification narrative
    # wins; AI step-by-step must not be shown as a remediation plan.
    rem = generate_remediation("CVE-2021-44228", store=index_store)
    assert rem["remediation_source"] == "ai"
    assert rem["applicable"] == "UNKNOWN"
    assert rem["step_by_step_fix"] != FAKE_NARRATIVE["step_by_step_fix"]
    assert "verification required" in rem["recommended_action"].lower()


def test_ai_remediation_falls_back_to_templates(index_store):
    rem = generate_remediation("CVE-2021-44228", store=index_store)
    assert rem["remediation_source"] == "template"
    assert isinstance(rem["step_by_step_fix"], list)
    assert rem["step_by_step_fix"]
    assert "log4j" in (rem["executive_summary"] or "").lower()


def test_ai_remediation_malformed_output_falls_back(monkeypatch, index_store):
    monkeypatch.setattr(
        "depwolf.application.remediation._ai_narrative",
        lambda cve_id, facts, context: None,
    )
    rem = generate_remediation("CVE-2021-44228", store=index_store)
    assert rem["remediation_source"] == "template"
    assert rem["executive_summary"], "deterministic summary present"


def test_ai_narrative_requires_api_key(monkeypatch):
    monkeypatch.delenv("AVIP_OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert _ai_narrative("CVE-2021-44228", {"product": "log4j"}) is None


def test_ai_narrative_parses_success_response(monkeypatch):
    import json

    payload = json.dumps(
        {
            "choices": [{"message": {"content": json.dumps(FAKE_NARRATIVE)}}],
        }
    ).encode()

    monkeypatch.setenv("AVIP_OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(
        "urllib.request.urlopen",
        _fake_urlopen(payload),
    )
    out = _ai_narrative("CVE-2021-44228", dict(_FACTS))
    assert out is not None
    assert out["executive_summary"] == FAKE_NARRATIVE["executive_summary"]
    assert out["verification"] == FAKE_NARRATIVE["verification"]


_FACTS = {
    "product": "log4j",
    "vendor": "apache",
    "cvss_score": 10.0,
    "cvss_severity": "CRITICAL",
    "kev": True,
    "risk_score": 99.3,
    "patch_priority": "Immediate",
    "fixed_version": "2.15.0",
    "affected_versions": [">= 2.0, < 2.15.0"],
    "description": "JNDI features do not protect against LDAP",
}


class _FakeResp:
    """Context-manager response whose read() returns the given bytes."""

    def __init__(self, payload: bytes):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._payload


def _fake_urlopen(payload):
    return lambda *a, **k: _FakeResp(payload)


def test_ai_narrative_graceful_on_network_error(monkeypatch):
    import urllib.error

    monkeypatch.setenv("AVIP_OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda *a, **k: (_ for _ in ()).throw(urllib.error.URLError("down")),
    )
    assert _ai_narrative("CVE-2021-44228", dict(_FACTS)) is None


def test_ai_narrative_graceful_on_invalid_json(monkeypatch):
    monkeypatch.setenv("AVIP_OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(
        "urllib.request.urlopen",
        _fake_urlopen(b'{"choices":[{"message":{"content":"not json"}}]}'),
    )
    assert _ai_narrative("CVE-2021-44228", dict(_FACTS)) is None


def test_ai_narrative_rejects_missing_keys(monkeypatch):
    import json

    payload = json.dumps(
        {
            "choices": [{"message": {"content": json.dumps({"executive_summary": "x"})}}],
        }
    ).encode()

    monkeypatch.setenv("AVIP_OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(
        "urllib.request.urlopen",
        _fake_urlopen(payload),
    )
    assert _ai_narrative("CVE-2021-44228", dict(_FACTS)) is None


# ---- verification (FIXED / STILL VULNERABLE / UNABLE TO VERIFY) ----------


def test_verify_fix_statuses(index_store):
    # CVE-2021-44228 affects 2.0 <= v < 2.15.0
    assert verify_fix("CVE-2021-44228", "2.14.0", store=index_store) == "still_vulnerable"
    assert verify_fix("CVE-2021-44228", "2.15.0", store=index_store) == "fixed"
    assert verify_fix("CVE-2021-44228", "1.9", store=index_store) == "fixed"  # below range
    assert verify_fix("CVE-2021-44228", "3.0", store=index_store) == "fixed"  # above range


def test_verify_fix_unable_never_maps_to_fixed(index_store):
    assert verify_fix("CVE-2021-44228", None, store=index_store) == "unable_to_verify"
    assert verify_fix("CVE-9999-0000", "1.0", store=index_store) == "unable_to_verify"
    assert verify_fix("", "1.0", store=index_store) == "unable_to_verify"


# ---- ecosystem-aware remediation -----------------------------------------


def test_remediation_maven_ecosystem(index_store):
    rem = generate_remediation(
        "CVE-2021-44228",
        store=index_store,
        context={
            "installed_version": "2.14.1",
            "ecosystem": "java",
            "group": "org.apache.logging.log4j",
            "artifact": "log4j-core",
            "manifest": "pom.xml",
            "direct": True,
            "version_confidence": "EXACT",
            "version_source": "manifest",
        },
    )
    assert rem["ecosystem"] == "java"
    assert rem["installed_version"] == "2.14.1"
    assert rem["applicable"] == "YES"
    assert rem["version_confidence"] == "EXACT"
    assert rem["version_source"] == "manifest"
    assert rem["dependency_type"] == "DIRECT"
    assert rem["applicability_note"] is None
    assert rem["minimum_safe_version"] == "2.15.0"
    assert rem["fixed_version"] == "2.15.0"
    assert any("mvn dependency:tree" in c for c in rem["patch_commands"])
    assert rem["file_change"]["manifest"] == "pom.xml"
    assert rem["file_change"]["after"] == "<version>2.15.0</version>"
    assert rem["verification"], "template verification is non-null"
    assert rem["remediation_source"] == "template"


def test_remediation_npm_commands(index_store):
    rem = generate_remediation(
        "CVE-2021-44228",
        store=index_store,
        context={
            "installed_version": "2.14.1",
            "ecosystem": "npm",
            "artifact": "log4j-core",
            "manifest": "package.json",
            "direct": True,
        },
    )
    assert any(c.startswith("npm install log4j-core@2.15.0") for c in rem["patch_commands"])
    assert rem["file_change"]["after"] == '"log4j-core": "2.15.0"'


def test_remediation_transitive_explanation(index_store):
    rem = generate_remediation(
        "CVE-2021-44228",
        store=index_store,
        context={
            "installed_version": "2.14.1",
            "ecosystem": "java",
            "group": "org.apache.logging.log4j",
            "artifact": "log4j-core",
            "manifest": "pom.xml",
            "direct": False,
            "path": ("app", "starter", "log4j-core"),
        },
    )
    assert "transitive" in rem["transitive_explanation"].lower()
    assert "app > starter > log4j-core" in rem["transitive_explanation"]
    assert rem["dependency_path"] == ["app", "starter", "log4j-core"]
    assert rem["dependency_type"] == "TRANSITIVE"


def test_remediation_version_not_affected(index_store):
    rem = generate_remediation(
        "CVE-2021-44228",
        store=index_store,
        context={"installed_version": "1.0", "ecosystem": "java", "artifact": "log4j-core", "direct": True},
    )
    assert rem["applicable"] == "NO"
    assert "outside the affected ranges" in rem["recommended_action"]


def test_remediation_compatibility_warning(index_store):
    rem = generate_remediation(
        "CVE-2021-44228",
        store=index_store,
        context={"installed_version": "1.9", "ecosystem": "java", "artifact": "log4j-core", "direct": True},
    )
    # 1.9 is below the affected range (2.0 <= v < 2.15.0) -> NO. Nothing is
    # recommended, so no compatibility warning and no patch commands are emitted.
    assert rem["applicable"] == "NO"
    assert rem["compatibility_warning"] is None
    assert rem["patch_commands"] == []


def test_remediation_standalone_infers_known_ecosystem(index_store):
    # No scan context: standalone `depwolf remediate CVE-...` infers the known
    # library ecosystem so log4j gets real Maven commands instead of a generic
    # OS advisory, while staying honest about missing version context. Without
    # an installed version the verdict is UNKNOWN: only version-check commands
    # are offered, never an upgrade.
    rem = generate_remediation("CVE-2021-44228", store=index_store)
    assert rem["ecosystem"] == "java"
    assert rem["package"] == "log4j-core"
    assert rem["installed_version"] is None
    assert rem["applicable"] == "UNKNOWN"
    assert "resolved version could not be determined" in rem["applicability_note"]
    assert rem["version_confidence"] == "UNKNOWN"
    assert rem["version_source"] == "unavailable"
    assert rem["dependency_type"] == "UNKNOWN"
    assert rem["dependency_path"] is None
    assert any("mvn dependency:tree" in c for c in rem["patch_commands"])
    assert not any("mvn versions:use-dep-version" in c for c in rem["patch_commands"])
    assert "org.apache.logging.log4j:log4j-core" in " ".join(rem["patch_commands"])
    assert rem["recommended_action"].startswith("VERIFICATION REQUIRED")
