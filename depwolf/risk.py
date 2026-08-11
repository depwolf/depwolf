"""Compatibility shim — real code lives in depwolf.domain.risk."""

from depwolf.domain.risk import (  # noqa: F401
    INTRINSIC_WEIGHTS,
    LABELS,
    RiskFactor,
    RiskResult,
    calculate_risk,
)
