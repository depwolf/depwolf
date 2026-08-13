"""CLI input robustness: BOM tolerance and graceful handling of bad JSON files."""

import json

from depwolf.interfaces.cli import _collect_findings, _parse_text_or_json


def test_parse_text_or_json_strips_bom():
    payload = json.dumps({"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2021-44228"}]}]})
    data = _parse_text_or_json("\ufeff" + payload)
    assert isinstance(data, dict)
    assert data["Results"][0]["Vulnerabilities"][0]["VulnerabilityID"] == "CVE-2021-44228"


def test_parse_text_or_json_raises_value_error_on_malformed():
    try:
        _parse_text_or_json('{"a": }')
    except ValueError as e:
        assert "invalid JSON input" in str(e)
    else:
        raise AssertionError("expected ValueError for malformed JSON")


def test_collect_findings_skips_bad_json_files(tmp_path, capsys):
    good = tmp_path / "trivy-good.json"
    good.write_text(
        json.dumps({"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2021-44228"}]}]}),
        encoding="utf-8",
    )
    bad = tmp_path / "broken.json"
    bad.write_text('{"Results": ', encoding="utf-8")

    refs = _collect_findings([str(tmp_path)])
    assert len(refs) == 1
    assert refs[0].cve_id == "CVE-2021-44228"
    assert refs[0].source == "trivy"

    err = capsys.readouterr().err
    assert "could not read" in err
    assert "broken.json" in err
