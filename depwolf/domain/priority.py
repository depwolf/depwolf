"""Patch priority / SLA computation, decoupled from risk scoring.

ADR (risk/priority/policy separation): ``calculate_risk`` returns an
unweighted-for-action score; the urgency classification (Immediate / 24 Hours /
72 Hours / 7 Days / 30 Days) is a separate concern that policies can override.
"""

from __future__ import annotations


def compute_patch_priority(score: float, kev: bool, epss: float | None, cvss: float | None) -> tuple[str, int]:
    if kev and score >= 80:
        return "Immediate", 4
    if kev:
        return "24 Hours", 24
    if score >= 85:
        return "Immediate", 4
    if score >= 65 or (epss and epss >= 0.7):
        return "24 Hours", 24
    if score >= 40 or (epss and epss >= 0.4):
        return "72 Hours", 72
    if score >= 20:
        return "7 Days", 168
    return "30 Days", 720
