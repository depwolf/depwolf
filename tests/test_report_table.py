"""Table rendering: box-drawn, truncating, deterministic (no ANSI when piped)."""

import sys
from unittest import mock

from depwolf.interfaces.report import render_remediation_table, render_table

_RESULT = {
    "total_scanned": 148,
    "actionable": 53,
    "not_applicable": 4,
    "risk_suppressed": 91,
    "reduction_rate": 64.2,
    "not_applicable_rate": 2.7,
    "false_positive_rate": 2.7,
    "prioritized": [
        {
            "cve_id": "CVE-2021-44228",
            "pkg": "log4j-core",
            "installed_version": "2.14.1",
            "severity": "Critical",
            "risk_score": 93.7,
            "fixed_version": "2.17.1",
            "patch_priority": "high",
            "match_confidence": "exact",
        },
        {
            "cve_id": "CVE-2021-39144",
            "pkg": "com.thoughtworks.xstream:xstream",
            "installed_version": "1.4.17",
            "severity": "High",
            "risk_score": 93.7,
            "fixed_version": "1.4.18",
            "patch_priority": "high",
            "match_confidence": "exact",
        },
    ],
    "filtered_details": [{"reason": "risk_suppressed"}] * 91
    + [{"reason": "not_in_stack"}] * 3
    + [{"reason": "not_found"}] * 1,
}


def test_render_table_box_drawn_and_summarized():
    out = render_table(_RESULT)
    assert "╔" in out and "╚" in out
    assert "┌" in out and "└" in out
    assert "DEPWOLF — prioritized findings" in out
    assert "candidates: 148" in out
    assert "CVE-2021-44228" in out
    assert "Filtered: 91x risk_suppressed" in out
    assert "\x1b[" not in out


def test_render_table_truncates_long_cells():
    out = render_table(_RESULT)
    assert "com.thoughtworks.xs…" in out
    assert "com.thoughtworks.xstream:xstream" not in out


def test_render_table_no_ansi_when_piped():
    with mock.patch.object(sys.stdout, "isatty", return_value=False):
        assert "\x1b[" not in render_table(_RESULT)


def test_render_table_colors_only_on_tty():
    import re

    with mock.patch.object(sys.stdout, "isatty", return_value=True):
        out = render_table(_RESULT)
    assert "\x1b[" in out
    stripped = re.sub(r"\x1b\[[0-9;]*m", "", out)
    lines = stripped.splitlines()
    top = lines.index(next(ln for ln in lines if ln.startswith("┌")))
    bot = lines.index(next(ln for ln in lines if ln.startswith("└")))
    rows = lines[top : bot + 1]
    widths = {len(ln) for ln in rows}
    assert len(widths) == 1, f"misaligned table rows: {widths}"


_REMED = {
    "cve_id": "CVE-2021-39144",
    "found": True,
    "package": "com.thoughtworks.xstream:xstream",
    "product": "xstream",
    "ecosystem": "java",
    "severity": "High",
    "risk_score": 93.7,
    "fixed_version": "1.4.18",
    "minimum_safe_version": "1.4.18",
    "applicable": None,
    "patch_priority": "Immediate",
    "remediation_source": "template",
    "kev": True,
    "recommended_action": "Upgrade com.thoughtworks.xstream:xstream to 1.4.18 or later.",
    "patch_commands": [
        "mvn versions:use-dep-version -Dincludes=com.thoughtworks.xstream:xstream -DdepVersion=1.4.18",
        "mvn dependency:tree -Dincludes=com.thoughtworks.xstream:xstream",
    ],
    "verification": "mvn dependency:tree -Dincludes=com.thoughtworks.xstream:xstream; "
    "Rerun 'depwolf scan .' and confirm CVE-2021-39144 no longer appears.",
    "step_by_step_fix": ["1. Upgrade the dependency", "2. Rerun the scan"],
}

_REMED_NOT_FOUND = {"cve_id": "CVE-9999-0000", "found": False}


def test_render_remediation_table_overview_and_cards():
    out = render_remediation_table([_REMED, _REMED_NOT_FOUND], threshold=60)
    assert "DEPWOLF — remediation" in out
    assert "remediating: 2 CVE(s)" in out
    assert "at/above threshold 60: 1" in out
    assert "CVE-2021-39144" in out
    assert "╭── CVE-2021-39144 · com.thoughtworks.xstream:xstream · java" in out
    assert "mvn versions:use-dep-version" in out
    assert "verify mvn dependency:tree" in out
    assert "CVE-9999-0000 not found in local CVE index" in out
    assert "\x1b[" not in out


def test_render_remediation_table_no_applicable_column():
    yes = dict(_REMED, applicable=True)
    no = dict(_REMED, applicable=False)
    out = render_remediation_table([yes, no])
    assert "Applicable" not in out
    assert render_remediation_table([yes]) == render_remediation_table([no])
    assert "CVE-2021-39144" in out


def test_render_remediation_table_no_threshold_banner():
    out = render_remediation_table([_REMED])
    assert "at/above threshold" not in out
