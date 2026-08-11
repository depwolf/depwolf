from depwolf.application.remediation import _ai_narrative
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
        lambda cve_id, facts: dict(FAKE_NARRATIVE),
    )
    rem = generate_remediation("CVE-2021-44228", store=index_store)
    assert rem["remediation_source"] == "ai"
    assert rem["executive_summary"] == FAKE_NARRATIVE["executive_summary"]
    assert rem["root_cause"] == FAKE_NARRATIVE["root_cause"]
    assert rem["step_by_step_fix"] == FAKE_NARRATIVE["step_by_step_fix"]
    assert rem["verification"] == FAKE_NARRATIVE["verification"]
    assert rem["fixed_version"] == "2.15.0"
    assert rem["patch_commands"], "patch commands stay DB-grounded"
    assert "log4j-core" in rem["patch_commands"][0]


def test_ai_remediation_falls_back_to_templates(index_store):
    rem = generate_remediation("CVE-2021-44228", store=index_store)
    assert rem["remediation_source"] == "template"
    assert isinstance(rem["step_by_step_fix"], list)
    assert rem["step_by_step_fix"]
    assert "log4j" in (rem["executive_summary"] or "").lower()


def test_ai_remediation_malformed_output_falls_back(monkeypatch, index_store):
    monkeypatch.setattr(
        "depwolf.application.remediation._ai_narrative",
        lambda cve_id, facts: None,
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
