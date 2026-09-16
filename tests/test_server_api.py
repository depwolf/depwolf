"""Server tests: exercise the FastAPI CVE query endpoints against a temp index."""

from __future__ import annotations

import sqlite3

import pytest
from fastapi.testclient import TestClient

from depwolf.infrastructure.cpe_index import _ensure_schema
from server import main
from tests.conftest import LOG4J_ROWS


@pytest.fixture
def client(tmp_path, monkeypatch):
    db = tmp_path / "cpe_index.db"
    conn = sqlite3.connect(str(db))
    _ensure_schema(conn)
    conn.executemany(
        """INSERT INTO cpe_index
           (vendor, product, version_start_including, version_start_excluding,
            version_end_including, version_end_excluding, cve_id, description,
            cvss_score, cvss_severity, epss_score, kev, published_date)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        LOG4J_ROWS,
    )
    conn.commit()
    conn.close()
    monkeypatch.setenv("AVIP_DB_PATH", str(db))
    monkeypatch.delenv("AVIP_SERVER_API_KEY", raising=False)
    with TestClient(main.app) as c:
        yield c


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"


def test_get_cve(client):
    r = client.get("/api/cve/CVE-2021-44228")
    assert r.status_code == 200
    ranges = r.json()
    assert len(ranges) == 1
    assert ranges[0]["cve_id"] == "CVE-2021-44228"
    assert ranges[0]["vendor"] == "apache"
    assert ranges[0]["product"] == "log4j"
    assert ranges[0]["cvss_score"] == 10.0
    assert ranges[0]["kev"] is True


def test_get_cve_not_found(client):
    r = client.get("/api/cve/CVE-9999-9999")
    assert r.status_code == 200
    assert r.json() == []


def test_cves_by_ids(client):
    r = client.post("/api/cves/by-ids", json={"cve_ids": ["CVE-2021-44228", "CVE-2021-45046", "CVE-9999-0000"]})
    assert r.status_code == 200
    data = r.json()
    assert len(data["CVE-2021-44228"]) == 1
    assert len(data["CVE-2021-45046"]) == 1
    assert data["CVE-9999-0000"] == []


def test_cves_by_products(client):
    r = client.post("/api/cves/by-products", json=[{"vendor": "apache", "product": "log4j"}])
    assert r.status_code == 200
    data = r.json()
    assert "apache|log4j" in data
    assert len(data["apache|log4j"]) == 2


def test_resolve_products(client):
    r = client.post("/api/resolve-products", json={"names": ["log4j"], "limit": 25})
    assert r.status_code == 200
    data = r.json()
    assert any(m["product"] == "log4j" for m in data.get("log4j", []))


def test_ignore_roundtrip(client):
    assert client.get("/api/ignored").json() == {"ignored": []}
    r = client.post("/api/ignore", json={"cve_id": "CVE-2021-44228"})
    assert r.status_code == 200
    assert "CVE-2021-44228" in client.get("/api/ignored").json()["ignored"]
    r = client.delete("/api/ignore/CVE-2021-44228")
    assert r.status_code == 200
    assert client.get("/api/ignored").json() == {"ignored": []}


def test_api_key_required(monkeypatch, tmp_path):
    db = tmp_path / "cpe_index.db"
    conn = sqlite3.connect(str(db))
    _ensure_schema(conn)
    conn.close()
    monkeypatch.setenv("AVIP_DB_PATH", str(db))
    monkeypatch.setenv("AVIP_SERVER_API_KEY", "secret-123")
    with TestClient(main.app) as c:
        assert c.get("/api/cve/CVE-2021-44228").status_code == 401
        r = c.get("/api/cve/CVE-2021-44228", headers={"X-API-Key": "secret-123"})
        assert r.status_code == 200