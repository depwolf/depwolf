from dataclasses import dataclass


@dataclass(frozen=True)
class RiskFactor:
    name: str
    weight: float
    raw_value: float
    contribution: float
    display_label: str


@dataclass(frozen=True)
class RiskResult:
    score: float
    severity: str
    confidence: float
    factors: dict[str, float]
    contributors: list[RiskFactor]


INTRINSIC_WEIGHTS = {
    "cvss": 0.3846,
    "epss": 0.3077,
    "kev": 0.3077,
}

LABELS = {
    "cvss": "CVSS Base Score",
    "epss": "EPSS Exploit Probability",
    "kev": "CISA KEV Listed",
}


def _normalize_cvss(raw: float | None) -> float:
    if raw is None:
        return 0.0
    return max(0.0, min(raw / 10.0, 1.0))


def _normalize_epss(raw: float | None) -> float:
    if raw is None:
        return 0.0
    return max(0.0, min(raw, 1.0))


def _normalize_boolean(val: bool) -> float:
    return 1.0 if val else 0.0


def calculate_risk(
    *,
    cvss: float | None = None,
    epss: float | None = None,
    kev: bool = False,
    evidence_count: int = 0,
) -> RiskResult:
    """Compute the deterministic AVIP risk score.

    Score is the weighted blend of CVSS (0.3846), EPSS (0.3077), and CISA KEV
    (0.3077), normalized to 0-100. Patch priority/SLA are a policy concern and
    live in ``depwolf.domain.priority`` (ADR: risk/priority/policy separation).
    """
    raw = {
        "cvss": _normalize_cvss(cvss),
        "epss": _normalize_epss(epss),
        "kev": _normalize_boolean(kev),
    }

    contributors = []
    weighted_sum = 0.0
    for key, weight in INTRINSIC_WEIGHTS.items():
        contribution = weight * raw[key]
        weighted_sum += contribution
        contributors.append(
            RiskFactor(
                name=key,
                weight=weight,
                raw_value=raw[key],
                contribution=round(contribution, 4),
                display_label=LABELS[key],
            )
        )

    adjusted = round(min(100.0, 100.0 * weighted_sum), 1)
    severity = (
        "Critical"
        if adjusted >= 80
        else "High"
        if adjusted >= 60
        else "Medium"
        if adjusted >= 35
        else "Low"
        if adjusted >= 10
        else "Informational"
    )
    confidence = min(1.0, evidence_count / 3)

    contributors_sorted = sorted(contributors, key=lambda c: c.contribution, reverse=True)
    factor_dict = {c.name: round(c.contribution, 4) for c in contributors_sorted}

    return RiskResult(
        score=adjusted,
        severity=severity,
        confidence=confidence,
        factors=factor_dict,
        contributors=contributors_sorted,
    )
