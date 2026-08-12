"""Shared test fixtures: a small but real CVE index for the whole suite.

Phase 0 goal: ``pytest`` runs with zero env vars. Instead of the old
``AVIP_DB_PATH`` + ``skipif`` pattern, tests inject an ``IndexStore`` built
here (temp-file DB or shared in-memory DB) with the same log4j rows that the
manual mini index uses.
"""

import sqlite3
from pathlib import Path

import pytest

from depwolf.infrastructure.cpe_index import _ensure_schema
from depwolf.infrastructure.store import SqliteIndexStore


@pytest.fixture(autouse=True)
def _isolate_signing_keys(monkeypatch):
    """Keep tests hermetic: ignore any real ~/.depwolf signing keypair."""
    from depwolf.infrastructure import index_sync

    monkeypatch.setenv(index_sync.SIGNING_KEY_ENV, "")
    monkeypatch.setenv("AVIP_SIGNING_PUBKEY_PATH", "")
    monkeypatch.delenv(index_sync.PUBKEY_ENV, raising=False)


LOG4J_ROWS = [
    (
        "apache",
        "log4j",
        "2.0",
        None,
        None,
        "2.15.0",
        "CVE-2021-44228",
        "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features do not protect "
        "against attacker controlled LDAP and other JNDI related endpoints",
        10.0,
        "CRITICAL",
        0.9757,
        1,
        "2021-12-10T10:00:00.000",
    ),
    (
        "apache",
        "log4j",
        "2.15.0",
        None,
        None,
        "2.16.0",
        "CVE-2021-45046",
        "Apache Log4j2 versions 2.15.0 incomplete fix for CVE-2021-44228",
        9.0,
        "CRITICAL",
        0.5,
        1,
        "2021-12-14T10:00:00.000",
    ),
]


def _seed(conn: sqlite3.Connection) -> None:
    conn.executemany(
        """INSERT INTO cpe_index
           (vendor, product, version_start_including, version_start_excluding,
            version_end_including, version_end_excluding, cve_id, description,
            cvss_score, cvss_severity, epss_score, kev, published_date)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        LOG4J_ROWS,
    )
    conn.commit()


def _build_file_index(path: Path) -> None:
    db = sqlite3.connect(str(path))
    _ensure_schema(db)
    _seed(db)
    db.close()


@pytest.fixture
def index_store(tmp_path):
    """Temp-file store with the log4j rows; writes (ignore list) persist per test."""
    path = tmp_path / "cpe_index.db"
    _build_file_index(path)
    return SqliteIndexStore(path)


@pytest.fixture
def memory_index_store():
    """Shared in-memory store with the log4j rows; exercises memory mode."""
    store = SqliteIndexStore(memory=True)
    _seed(store.open())
    return store
