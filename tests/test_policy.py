"""Phase 6 tests: declarative policy engine + risk/priority separation."""

from depwolf.domain.policy import (
    apply_policy,
    default_policy,
    dump_policy,
    load_policy,
)
from depwolf.domain.priority import compute_patch_priority
from depwolf.domain.risk import RiskResult, calculate_risk


def test_risk_result_has_no_priority_fields():
    r = calculate_risk(cvss=10.0, epss=0.97, kev=True, evidence_count=1)
    assert isinstance(r, RiskResult)
    assert not hasattr(r, "patch_priority")
    assert not hasattr(r, "patch_sla_hours")
    assert r.score == 99.1
    assert r.severity == "Critical"


def test_priority_separate_from_risk():
    risk = calculate_risk(cvss=10.0, epss=0.97, kev=True, evidence_count=1)
    priority, sla = compute_patch_priority(risk.score, True, 0.97, 10.0)
    assert priority == "Immediate"
    assert sla == 4


def test_default_policy_allows_high_risk():
    v = apply_policy(
        default_policy(),
        cve_id="CVE-2021-44228",
        risk_score=100.0,
        severity="Critical",
        kev=True,
        epss=0.97,
        cvss=10.0,
        fixed_version="2.15.0",
    )
    assert v.decision == "allow"
    assert v.patch_priority == "Immediate"
    assert v.sla_hours == 4


def test_min_risk_floor_denies():
    p = default_policy().with_overrides(min_risk=50.0)
    v = apply_policy(
        p,
        cve_id="CVE-2021-44228",
        risk_score=40.0,
        severity="High",
        kev=False,
        epss=0.1,
        cvss=7.5,
        fixed_version=None,
    )
    assert v.decision == "deny"
    assert v.rule == "min_risk"


def test_require_fixed_warns():
    p = default_policy().with_overrides(require_fixed=True)
    v = apply_policy(
        p,
        cve_id="CVE-2021-45046",
        risk_score=90.0,
        severity="Critical",
        kev=True,
        epss=0.5,
        cvss=9.0,
        fixed_version=None,
    )
    assert v.decision == "warn"
    assert v.rule == "require_fixed"


def test_blocklist_denies():
    p = default_policy().with_overrides(blocklist=frozenset({"CVE-2021-44228"}))
    v = apply_policy(
        p,
        cve_id="CVE-2021-44228",
        risk_score=100.0,
        severity="Critical",
        kev=True,
        epss=0.97,
        cvss=10.0,
        fixed_version="2.15.0",
    )
    assert v.decision == "deny"
    assert v.rule == "blocklist"


def test_severity_gate_warns():
    p = load_policy(
        "severity_gates:\n  High: warn\n  Critical: allow\n  Medium: allow\n  Low: allow\n  Informational: allow\n"
    )
    v = apply_policy(
        p,
        cve_id="CVE-2021-45046",
        risk_score=85.0,
        severity="High",
        kev=True,
        epss=0.5,
        cvss=9.0,
        fixed_version="2.16.0",
    )
    assert v.decision == "warn"


def test_policy_roundtrip():
    p = load_policy(dump_policy(default_policy()))
    assert p.min_risk == default_policy().min_risk
    assert p.threshold == default_policy().threshold
