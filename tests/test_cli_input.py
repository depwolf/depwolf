"""CLI input robustness: BOM tolerance and graceful handling of bad JSON files."""

import json
import sqlite3

from depwolf.interfaces.cli import _collect_findings, _parse_text_or_json, _require_db


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


def _empty_index_db(path) -> None:
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE cpe_index (cve_id TEXT)")
    conn.commit()
    conn.close()


def test_require_db_redownloads_empty_index(tmp_path, monkeypatch, capsys):
    import depwolf.interfaces.cli as cli

    db_path = tmp_path / "cpe_index.db"
    _empty_index_db(db_path)
    monkeypatch.setattr(cli, "DB_PATH", db_path)

    downloaded = []

    def fake_download(*a, **k):
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE IF NOT EXISTS cpe_index (cve_id TEXT)")
        conn.execute("INSERT INTO cpe_index (cve_id) VALUES ('CVE-2021-44228')")
        conn.commit()
        conn.close()
        downloaded.append(True)
        return True

    monkeypatch.setattr("depwolf.infrastructure.cpe_index.download_index", fake_download)

    assert _require_db() is True
    assert downloaded == [True]
    err = capsys.readouterr().err
    assert "empty" in err


def test_require_db_rejects_empty_index_without_network(tmp_path, monkeypatch, capsys):
    import depwolf.interfaces.cli as cli

    db_path = tmp_path / "cpe_index.db"
    _empty_index_db(db_path)
    monkeypatch.setattr(cli, "DB_PATH", db_path)
    monkeypatch.setattr("depwolf.infrastructure.cpe_index.download_index", lambda *a, **k: False)

    assert _require_db() is False
    err = capsys.readouterr().err
    assert "no usable index" in err


def test_remediate_table_default_prints_table_and_gate(tmp_path, monkeypatch, capsys):
    import depwolf.interfaces.cli as cli
    from tests.conftest import _build_file_index

    db_path = tmp_path / "cpe_index.db"
    _build_file_index(db_path)
    monkeypatch.setattr(cli, "DB_PATH", db_path)
    monkeypatch.setattr("depwolf.infrastructure.store.DB_PATH", db_path)

    # No saved scan state: applicability is UNKNOWN -> verification required,
    # never a confirmed finding, so the CI gate passes (rc 0).
    rc = cli._remediate(["CVE-2021-44228"], 60)
    assert rc == 0
    out, err = capsys.readouterr()
    assert "DEPWOLF — remediation" in out
    assert "CVE-2021-44228" in out
    assert "VERIFICATION REQUIRED" in out
    assert "[gate]" in err
    assert "no confirmed findings" in err


def test_remediate_json_format_still_structured(tmp_path, monkeypatch, capsys):
    import depwolf.interfaces.cli as cli
    from tests.conftest import _build_file_index

    db_path = tmp_path / "cpe_index.db"
    _build_file_index(db_path)
    monkeypatch.setattr(cli, "DB_PATH", db_path)
    monkeypatch.setattr("depwolf.infrastructure.store.DB_PATH", db_path)

    rc = cli._remediate(["CVE-2021-44228"], 60, fmt="json")
    assert rc == 0
    out, _err = capsys.readouterr()
    data = json.loads(out)
    assert data["remediation"][0]["fixed_version"] == "2.15.0"
    assert data["remediation"][0]["applicable"] == "UNKNOWN"
