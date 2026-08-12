"""Phase 6 tests: signed/checksummed index sync (P2-1)."""

import base64
import json

from depwolf.infrastructure.index_sync import (
    MANIFEST_NAME,
    PUBKEY_ENV,
    SIGNING_KEY_ENV,
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


def _gen_key(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    priv = tmp_path / "sign.pem"
    priv.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    raw_pub = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return priv, base64.b64encode(raw_pub).decode()


def test_signed_manifest_verifies_with_correct_pubkey(tmp_path, monkeypatch):
    priv, pub_b64 = _gen_key(tmp_path)
    monkeypatch.setenv(SIGNING_KEY_ENV, str(priv))
    db = tmp_path / "cpe_index.db"
    db.write_bytes(b"signed data")
    manifest = write_manifest(db)
    assert manifest["signed"] is True

    monkeypatch.setenv(PUBKEY_ENV, pub_b64)
    ok, detail = verify_index(db)
    assert ok
    assert "signature OK" in detail


def test_signed_manifest_rejected_on_wrong_pubkey(tmp_path, monkeypatch):
    priv, _ = _gen_key(tmp_path)
    monkeypatch.setenv(SIGNING_KEY_ENV, str(priv))
    db = tmp_path / "cpe_index.db"
    db.write_bytes(b"signed data")
    write_manifest(db)

    _, other_pub = _gen_key(tmp_path)
    monkeypatch.setenv(PUBKEY_ENV, other_pub)
    ok, detail = verify_index(db)
    assert not ok
    assert "signature verification failed" in detail


def test_signed_manifest_passes_without_pubkey(tmp_path, monkeypatch):
    priv, _ = _gen_key(tmp_path)
    monkeypatch.setenv(SIGNING_KEY_ENV, str(priv))
    db = tmp_path / "cpe_index.db"
    db.write_bytes(b"signed data")
    manifest = write_manifest(db)
    assert manifest["signed"] is True

    monkeypatch.delenv(PUBKEY_ENV, raising=False)
    ok, detail = verify_index(db)
    assert ok
    assert "no pubkey configured" in detail


class _ChunkedResp:
    """Context-manager response readable in chunks (copyfileobj-safe)."""

    def __init__(self, payload: bytes):
        self._payload = payload
        self._pos = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, n: int = -1):
        if self._pos >= len(self._payload):
            return b""
        if n is None or n < 0:
            data = self._payload[self._pos :]
        else:
            data = self._payload[self._pos : self._pos + n]
        self._pos += len(data)
        return data


def test_download_index_fetches_manifest_sidecar(tmp_path, monkeypatch):
    import sqlite3

    import depwolf.infrastructure.cpe_index as ci
    from depwolf.infrastructure.cpe_index import _ensure_schema

    db = tmp_path / "cpe_index.db"
    conn = sqlite3.connect(str(db))
    _ensure_schema(conn)
    conn.execute(
        """INSERT INTO cpe_index (vendor, product, cve_id)
           VALUES ('apache', 'log4j', 'CVE-2021-44228')"""
    )
    conn.execute("CREATE TABLE IF NOT EXISTS pad (b BLOB)")
    conn.execute("INSERT INTO pad VALUES (?)", (b"x" * 1_100_000,))
    conn.commit()
    conn.close()
    payload = db.read_bytes()  # > 1 MB minimum size check, and a valid sqlite DB

    digest = sha256_file(db)
    manifest = {
        "format": 1,
        "built_at": "2026-08-11T00:00:00+00:00",
        "files": {"cpe_index.db": digest},
        "signature": "",
        "signed": False,
    }
    manifest_payload = json.dumps(manifest).encode()
    sidecar_payload = f"{digest}  cpe_index.db\n".encode()

    target = tmp_path / "dl" / "cpe_index.db"
    monkeypatch.setattr(ci, "DB_PATH", target)

    def fake_urlopen(req, *a, **k):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if url.endswith(".sha256"):
            return _ChunkedResp(sidecar_payload)
        if url.endswith(".manifest.json"):
            return _ChunkedResp(manifest_payload)
        return _ChunkedResp(payload)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    monkeypatch.setenv("AVIP_DB_URL", "https://example.invalid/index/cpe_index.db")
    monkeypatch.delenv("AVIP_INDEX_SHA256", raising=False)
    monkeypatch.delenv("AVIP_INDEX_PUBKEY", raising=False)

    assert ci.download_index() is True
    assert target.exists()
    assert (target.parent / MANIFEST_NAME).read_bytes() == manifest_payload
