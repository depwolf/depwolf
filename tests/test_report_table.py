"""Table rendering: box-drawn, truncating, deterministic (no ANSI when piped)."""

import sys
from unittest import mock

from depwolf.interfaces.report import render_table

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
