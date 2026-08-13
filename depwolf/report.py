"""Compatibility shim — real code lives in depwolf.interfaces.report."""

from depwolf.interfaces.report import (  # noqa: F401
    build_json_report,
    build_sarif,
    render_remediation_table,
    render_table,
)
