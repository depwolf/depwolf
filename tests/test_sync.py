"""Phase 6 tests: signed/checksummed index sync (P2-1)."""

import json

from depwolf.infrastructure.index_sync import (
    MANIFEST_NAME,
    sha256_file,
    verify_index,
    write_manifest,
)


def test_sha256_file_deterministic(tmp_path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"hello world")
    assert sha256_file(p) == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    assert sha256_file(p) == sha256_file(p)


def test_write_manifest_unsigned_without_key(tmp_path):
    db = tmp_path / "cpe_index.db"
    db.write_bytes(b"fake sqlite bytes")
    manifest = write_manifest(db)
    assert manifest["files"][db.name] == sha256_file(db)
    assert manifest["signed"] is False
    assert (tmp_path / MANIFEST_NAME).exists()


def test_verify_index_checksum_ok(tmp_path):
    db = tmp_path / "cpe_index.db"
    db.write_bytes(b"fake sqlite bytes")
    write_manifest(db)
    ok, detail = verify_index(db)
    assert ok
    assert "sha256 OK" in detail


def test_verify_index_detects_tampering(tmp_path):
    db = tmp_path / "cpe_index.db"
    db.write_bytes(b"original")
    write_manifest(db)
    db.write_bytes(b"TAMPERED")
    ok, detail = verify_index(db)
    assert not ok
    assert "sha256 mismatch" in detail


def test_verify_index_missing_manifest_falls_back_to_table_check(tmp_path):
    import sqlite3

    db = tmp_path / "cpe_index.db"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE cpe_index (cve_id TEXT)")
    conn.close()
    ok, detail = verify_index(db)
    assert ok
    assert "no manifest" in detail

    bad = tmp_path / "other.db"
    bad.write_bytes(b"not a sqlite file")
    ok, detail = verify_index(bad)
    assert not ok


def test_manifest_json_is_well_formed(tmp_path):
    db = tmp_path / "cpe_index.db"
    db.write_bytes(b"data")
    write_manifest(db)
    data = json.loads((tmp_path / MANIFEST_NAME).read_text(encoding="utf-8"))
    assert data["format"] == 1
    assert data["built_at"]
