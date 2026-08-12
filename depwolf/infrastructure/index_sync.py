"""Signed/checksummed index sync (Phase 6, pulled forward).

Supply-chain protection for the prebuilt ``cpe_index.db``: every build writes a
``manifest.json`` next to the DB with per-file SHA-256 digests and (when a
signing key is configured) an Ed25519 signature over the digest list. Downloads
verify the sidecar ``*.sha256`` first, then the Ed25519 signature when a public
key is provided. Verification is cheap and pure-stdlib; Ed25519 signing/verify
uses the optional ``cryptography`` package.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path

logger = logging.getLogger(__name__)

MANIFEST_NAME = "manifest.json"
SIGNING_KEY_ENV = "AVIP_SIGNING_KEY_PATH"
PUBKEY_ENV = "AVIP_INDEX_PUBKEY"


def sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def _signing_key_path() -> Path | None:
    raw = os.environ.get(SIGNING_KEY_ENV, str(Path.home() / ".depwolf" / "index_signing.pem"))
    if not raw:  # explicitly disabled via empty env var
        return None
    p = Path(raw)
    return p if p.exists() else None


def _pubkey_configured() -> bool:
    if os.environ.get(PUBKEY_ENV):
        return True
    return _public_key_path() is not None


def _public_key_path() -> Path | None:
    raw = os.environ.get("AVIP_SIGNING_PUBKEY_PATH", str(Path.home() / ".depwolf" / "index_signing.pub.pem"))
    if not raw:  # explicitly disabled via empty env var
        return None
    p = Path(raw)
    return p if p.exists() else None


def _ed25519_available() -> bool:
    try:
        import cryptography  # noqa: F401

        return True
    except ImportError:
        return False


def _sign_bytes(data: bytes) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key_path = _signing_key_path()
    if key_path is None:
        return ""
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("index signing key must be an Ed25519 private key")
    return base64.b64encode(key.sign(data)).decode()


def _verify_signature(data: bytes, signature_b64: str) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    raw = None
    env = os.environ.get(PUBKEY_ENV)
    if env:
        try:
            raw = base64.b64decode(env)
        except Exception as e:
            logger.warning(f"AVIP_INDEX_PUBKEY is not valid base64: {e}")
            return False
    else:
        key_path = _public_key_path()
        if key_path is None:
            return False
        try:
            loaded = serialization.load_pem_public_key(key_path.read_bytes())
        except Exception as e:
            logger.warning(f"could not load index public key {key_path}: {e}")
            return False
        if not isinstance(loaded, Ed25519PublicKey):
            logger.warning("index public key is not Ed25519")
            return False
        raw = loaded.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    try:
        pub = Ed25519PublicKey.from_public_bytes(raw)
    except Exception as e:
        logger.warning(f"AVIP_INDEX_PUBKEY is not a valid Ed25519 public key: {e}")
        return False
    try:
        pub.verify(base64.b64decode(signature_b64), data)
        return True
    except InvalidSignature:
        return False


def write_manifest(db_path: Path) -> dict:
    """Write a signed/checksummed manifest next to a built index DB."""
    digest = sha256_file(db_path)
    manifest = {
        "format": 1,
        "built_at": datetime.now(UTC).isoformat(),
        "files": {db_path.name: digest},
        "signature": "",
        "signed": False,
    }
    if _ed25519_available():
        try:
            manifest["signature"] = _sign_bytes(json.dumps({"files": manifest["files"]}, sort_keys=True).encode())
            manifest["signed"] = bool(manifest["signature"])
        except Exception as e:
            logger.warning(f"index signing failed (manifest will be unsigned): {e}")
    manifest_path = db_path.parent / MANIFEST_NAME
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    logger.info(f"index manifest written to {manifest_path} (signed={manifest['signed']})")
    return manifest


def verify_index(db_path: Path) -> tuple[bool, str]:
    """Verify manifest checksum + signature for an index DB.

    Returns ``(ok, detail)``. With no manifest present, falls back to a bare
    ``cpe_index`` table check (same as before) so existing indexes keep working.
    """
    manifest_path = db_path.parent / MANIFEST_NAME
    if not manifest_path.exists():
        try:
            import sqlite3

            conn = sqlite3.connect(str(db_path))
            row = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cpe_index'").fetchone()
            conn.close()
        except Exception as e:
            return False, f"index unreadable: {e}"
        if not row:
            return False, "not a valid cpe_index.db (no cpe_index table)"
        return True, "no manifest.json — cpe_index table check only (not signed/checksummed)"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as e:
        return False, f"manifest unreadable: {e}"
    files = manifest.get("files") or {}
    expected = files.get(db_path.name)
    if not expected:
        return False, f"manifest does not list {db_path.name}"
    if not db_path.exists():
        return False, f"index file missing: {db_path}"
    actual = sha256_file(db_path)
    if actual.lower() != expected.lower():
        return False, f"sha256 mismatch (expected {expected}, got {actual})"
    if manifest.get("signed"):
        if not _pubkey_configured():
            return True, (
                f"{db_path.name} sha256 OK — signed manifest present but no pubkey "
                "configured (set AVIP_INDEX_PUBKEY to verify the signature)"
            )
        if not _verify_signature(
            json.dumps({"files": files}, sort_keys=True).encode(),
            manifest.get("signature", ""),
        ):
            return False, "Ed25519 signature verification failed"
        return True, f"{db_path.name} checksum + Ed25519 signature OK"
    return True, f"{db_path.name} sha256 OK (unsigned manifest — no signing key configured)"
