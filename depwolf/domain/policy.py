"""Declarative policy engine (Phase 6, pulled forward).

A ``Policy`` is a YAML-declarable set of rules evaluated against a finding's
risk + enrichment. The result is a ``PolicyVerdict`` (allow / warn / deny) plus
the patch priority/SLA the finding should carry. Defaults mirror the current
hardcoded behavior (risk floor 35, priority from ``domain.priority``), so the
funnel stays byte-compatible unless a policy overrides it.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field

import yaml

from depwolf.domain.model import PolicyVerdict
from depwolf.domain.priority import compute_patch_priority

ALLOW = "allow"
WARN = "warn"
DENY = "deny"


@dataclass(frozen=True)
class Policy:
    name: str = "default"
    version: str = "1"
    threshold: float = 60.0  # exit-code gate
    min_risk: float = 35.0  # report floor
    require_fixed: bool = False
    blocklist: frozenset[str] = frozenset()
    severity_gates: dict[str, str] = field(
        default_factory=lambda: {
            "Critical": "allow",
            "High": "allow",
            "Medium": "allow",
            "Low": "allow",
            "Informational": "allow",
        }
    )

    def with_overrides(self, **kwargs) -> Policy:
        data = dataclasses.asdict(self)
        data.update(kwargs)
        return Policy(**data)


def default_policy() -> Policy:
    return Policy()


def _severity_gates(data: dict) -> dict[str, str]:
    gates = {k.title(): str(v).lower() for k, v in (data or {}).items()}
    invalid = set(gates.values()) - {ALLOW, WARN, DENY}
    assert not invalid, f"policy severity_gates must use allow|warn|deny (found {invalid})"
    return gates


def load_policy(text: str) -> Policy:
    """Parse a policy YAML document (strict schema, fail loudly on typos)."""
    data = yaml.safe_load(text) or {}
    assert isinstance(data, dict), "policy must be a YAML mapping"
    return Policy(
        name=str(data.get("name", "default")),
        version=str(data.get("version", "1")),
        threshold=float(data.get("threshold", 60.0)),
        min_risk=float(data.get("min_risk", 35.0)),
        require_fixed=bool(data.get("require_fixed", False)),
        blocklist=frozenset(str(c).upper() for c in data.get("blocklist", [])),
        severity_gates=_severity_gates(data.get("severity_gates", {})),
    )


def dump_policy(policy: Policy) -> str:
    """Serialize a policy back to YAML (for `depwolf policy show`)."""
    return yaml.safe_dump(
        {
            "name": policy.name,
            "version": policy.version,
            "threshold": policy.threshold,
            "min_risk": policy.min_risk,
            "require_fixed": policy.require_fixed,
            "blocklist": sorted(policy.blocklist),
            "severity_gates": {k: v for k, v in policy.severity_gates.items()},
        },
        sort_keys=False,
    )


def apply_policy(
    policy: Policy,
    *,
    cve_id: str,
    risk_score: float,
    severity: str,
    kev: bool,
    epss: float | None,
    cvss: float | None,
    fixed_version: str | None,
    scanner_severity: str | None = None,
) -> PolicyVerdict:
    """Evaluate a finding against a policy. Deterministic; no I/O."""
    if cve_id.upper() in policy.blocklist:
        return PolicyVerdict(
            decision=DENY,
            reason="Blocklisted by policy",
            rule="blocklist",
            patch_priority=None,
            sla_hours=None,
        )
    if risk_score < policy.min_risk:
        return PolicyVerdict(
            decision=DENY,
            reason=f"Risk score below policy floor ({policy.min_risk})",
            rule="min_risk",
            patch_priority=None,
            sla_hours=None,
        )
    if policy.require_fixed and not fixed_version:
        return PolicyVerdict(
            decision=WARN,
            reason="No fixed version published (require_fixed)",
            rule="require_fixed",
            patch_priority=None,
            sla_hours=None,
        )

    gate = policy.severity_gates.get(severity.title(), ALLOW)
    priority, sla = compute_patch_priority(risk_score, kev, epss, cvss)
    return PolicyVerdict(
        decision=gate,
        reason=f"Severity gate {severity} -> {gate}" if gate != ALLOW else "Passes policy",
        rule=f"severity_gates.{severity.title()}" if gate != ALLOW else None,
        patch_priority=priority,
        sla_hours=sla,
    )
