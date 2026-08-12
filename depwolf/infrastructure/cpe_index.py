"""CVE index: sqlite persistence + NVD/EPSS/KEV sync + prebuilt-index download.

Owns the on-disk ``cpe_index.db`` (schema, build, download). The version/CPE
parsing helpers moved to ``depwolf.domain.versions``; consumers should read
through the ``IndexStore`` port (``depwolf.infrastructure.store``).
"""

import json
import logging
import os
import sqlite3
import time
import urllib.request
from pathlib import Path

from depwolf.domain.versions import _parse_cpe23

logger = logging.getLogger(__name__)

DB_PATH = Path(
    os.environ.get(
        "AVIP_DB_PATH",
        str(Path.home() / ".depwolf" / "cpe_index.db"),
    )
)

# Default prebuilt-index location: `depwolf sync` (and first `depwolf scan`)
# download this when no AVIP_DB_URL override is set. Hosted as a GitHub Release
# asset so `pip install depwolf` + `depwolf scan` works with zero configuration.
DEFAULT_DB_URL = "https://github.com/depwolf/depwolf/releases/download/index-v1/cpe_index.db"

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
RESULTS_PER_PAGE = 2000
REQ_DELAY = float(os.environ.get("AVIP_REQ_DELAY", "6.0"))
NVD_API_KEY = os.environ.get("AVIP_NVD_API_KEY") or ""


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cpe_index (
            vendor TEXT,
            product TEXT,
            version_start_including TEXT,
            version_start_excluding TEXT,
            version_end_including TEXT,
            version_end_excluding TEXT,
            cve_id TEXT,
            description TEXT,
            cvss_score REAL,
            cvss_severity TEXT,
            epss_score REAL,
            kev BOOLEAN DEFAULT 0,
            published_date TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_vendor_product ON cpe_index(vendor, product)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_id ON cpe_index(cve_id)")
    conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
    conn.commit()


def _init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(DB_PATH))
    _ensure_schema(db)
    return db


def _fetch_epss() -> dict:
    scores = {}
    sources = [
        "https://epss.cyentia.com/epss_scores-current.csv.gz",
        "https://api.first.org/data/v1/epss?limit=100000&offset=0",
    ]
    for src in sources:
        try:
            req = urllib.request.Request(src, headers={"User-Agent": "depwolf/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
            if src.endswith(".gz"):
                import gzip

                raw = gzip.decompress(raw)
                text = raw.decode("utf-8", errors="replace")
                for i, line in enumerate(text.splitlines()):
                    if i == 0 or line.startswith("#"):
                        continue
                    parts = line.split(",")
                    if len(parts) >= 2:
                        cve = parts[0].strip().upper()
                        if not cve.startswith("CVE-"):
                            continue
                        try:
                            scores[cve] = float(parts[1].strip())
                        except ValueError:
                            pass
            else:
                data = json.loads(raw)
                for item in data.get("data", []):
                    scores[item["cve"]] = float(item["epss"])
            break
        except Exception as e:
            logger.warning(f"EPSS fetch failed from {src}: {e}")
    logger.info(f"EPSS scores loaded: {len(scores)} CVEs")
    return scores


def _fetch_kev() -> set:
    try:
        req = urllib.request.Request(KEV_URL, headers={"User-Agent": "depwolf/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
        kev = {v["cveID"] for v in data.get("vulnerabilities", [])}
        logger.info(f"KEV list loaded: {len(kev)} CVEs")
        return kev
    except Exception as e:
        logger.warning(f"KEV fetch error: {e}")
        return set()


def fetch_nvd_page(start_index: int, last_mod_date: str | None = None) -> dict | None:
    url = f"{NVD_BASE}?startIndex={start_index}&resultsPerPage={RESULTS_PER_PAGE}"
    if last_mod_date:
        url += f"&lastModStartDate={last_mod_date}&lastModEndDate={last_mod_date.replace('T', 'T23:59:59.000')}"
    url += "&noRejected="
    if NVD_API_KEY:
        url += f"&apiKey={NVD_API_KEY}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "depwolf/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except Exception as e:
        logger.warning(f"NVD fetch error at {start_index}: {e}")
        return None


def download_index(url: str | None = None) -> bool:
    """Download a prebuilt cpe_index.db from cloud storage.

    Uses AVIP_DB_URL (or the explicit arg), streams to a temp file, verifies the
    sha256 sidecar (``<url>.sha256``) plus the local manifest when present,
    checks the sqlite file has the expected table, then swaps it into DB_PATH.
    Returns True on success. Never touches the existing DB on failure.
    """
    import shutil
    import tempfile

    from depwolf.infrastructure.index_sync import MANIFEST_NAME, sha256_file, verify_index

    url = url or os.environ.get("AVIP_DB_URL") or DEFAULT_DB_URL
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(suffix=".db", dir=str(DB_PATH.parent))
    os.close(fd)
    try:
        logger.info(f"Downloading prebuilt index from {url}")
        req = urllib.request.Request(url, headers={"User-Agent": "depwolf/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp, open(tmp, "wb") as out:
            shutil.copyfileobj(resp, out, length=1024 * 1024)
        size = os.path.getsize(tmp)
        if size < 1024 * 1024:
            raise ValueError(f"downloaded index too small ({size} bytes)")

        # Checksum + signature verification (P2-1): pull the .sha256 sidecar
        # and, when AVIP_INDEX_PUBKEY is set, verify the signed manifest.
        expected = os.environ.get("AVIP_INDEX_SHA256")
        if not expected:
            try:
                req = urllib.request.Request(f"{url}.sha256", headers={"User-Agent": "depwolf/1.0"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    expected = resp.read().decode().strip().split()[0]
            except Exception:
                logger.warning("no .sha256 sidecar available — skipping download checksum")
        if expected:
            actual = sha256_file(Path(tmp))
            if actual.lower() != expected.lower():
                raise ValueError(f"download checksum mismatch (expected {expected}, got {actual})")

        # Pull the signed manifest sidecar so signature verification works on a
        # fresh machine (when AVIP_INDEX_PUBKEY is configured). Optional — a
        # missing sidecar degrades to checksum + table verification.
        try:
            req = urllib.request.Request(f"{url}.manifest.json", headers={"User-Agent": "depwolf/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                (DB_PATH.parent / MANIFEST_NAME).write_bytes(resp.read())
            logger.info(f"Downloaded manifest sidecar from {url}.manifest.json")
        except Exception:
            logger.warning("no .manifest.json sidecar available — signature verification skipped")

        os.replace(tmp, DB_PATH)
        ok, detail = verify_index(DB_PATH)
        if not ok:
            raise ValueError(f"downloaded index failed verification: {detail}")

        check = sqlite3.connect(str(DB_PATH))
        row = check.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cpe_index'").fetchone()
        count = check.execute("SELECT COUNT(*) FROM cpe_index").fetchone()[0]
        check.close()
        if not row or count == 0:
            raise ValueError(f"downloaded file is not a valid cpe_index.db ({count} rows)")
        logger.info(f"Index ready: {DB_PATH} ({count:,} CVE/version rows) — {detail}")
        return True
    except Exception as e:
        logger.warning(f"Index download failed: {e}")
        try:
            os.remove(tmp)
        except OSError:
            pass
        return False


def build_index(full_sync: bool = False):
    if not full_sync and download_index():
        return
    db = _init_db()
    if full_sync:
        db.execute("DELETE FROM cpe_index")
        db.execute("DELETE FROM meta")
        db.commit()
        logger.info("Full sync — cleared existing index")
    last_mod = None
    if not full_sync:
        row = db.execute("SELECT value FROM meta WHERE key='last_mod'").fetchone()
        if row:
            last_mod = row[0]
            logger.info(f"Partial sync from {last_mod}")
    logger.info("Loading EPSS + KEV enrichment data...")
    epss_scores = _fetch_epss()
    kev_set = _fetch_kev()
    start = 0
    total_results = 1
    inserted = 0
    while start < total_results:
        data = fetch_nvd_page(start, last_mod)
        if not data:
            logger.warning(f"Failed at startIndex={start}, retrying in {REQ_DELAY}s")
            time.sleep(REQ_DELAY * 2)
            continue
        total_results = data.get("totalResults", 0)
        vulns = data.get("vulnerabilities", [])
        if start % (RESULTS_PER_PAGE * 5) == 0 or start + len(vulns) >= total_results:
            logger.info(f"NVD sync: {start + len(vulns)}/{total_results} CVEs fetched")
        for vuln in vulns:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            desc_data = cve.get("descriptions", [])
            description = next((d["value"] for d in desc_data if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            cvss_score = None
            cvss_severity = None
            for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version_key in metrics:
                    cvss_data = metrics[version_key][0]["cvssData"]
                    cvss_score = cvss_data.get("baseScore")
                    cvss_severity = cvss_data.get("baseSeverity")
                    break
            published = cve.get("published", "")
            configurations = cve.get("configurations", [])
            cpe_nodes = []
            for config in configurations:
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        cpe_nodes.append(match)
            if not cpe_nodes:
                for config in configurations:
                    for node in config.get("nodes", []):
                        for match in node.get("cpeMatch", []):
                            cpe_nodes.append(match)
            for match in cpe_nodes:
                criteria = match.get("criteria", "")
                parsed = _parse_cpe23(criteria)
                if not parsed:
                    continue
                if parsed["version"]:
                    start_i = parsed["version"]
                    start_e = None
                    end_i = match.get("versionEndIncluding")
                    end_e = match.get("versionEndExcluding")
                    if not end_i and not end_e:
                        end_i = parsed["version"]
                else:
                    start_i = match.get("versionStartIncluding")
                    start_e = match.get("versionStartExcluding")
                    end_i = match.get("versionEndIncluding")
                    end_e = match.get("versionEndExcluding")
                db.execute(
                    """
                    INSERT INTO cpe_index
                        (vendor, product, version_start_including, version_start_excluding,
                         version_end_including, version_end_excluding, cve_id, description,
                         cvss_score, cvss_severity, epss_score, kev, published_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        parsed["vendor"],
                        parsed["product"],
                        start_i,
                        start_e,
                        end_i,
                        end_e,
                        cve_id,
                        description,
                        cvss_score,
                        cvss_severity,
                        epss_scores.get(cve_id, 0.0),
                        1 if cve_id in kev_set else 0,
                        published,
                    ),
                )
                inserted += 1
        start += RESULTS_PER_PAGE
        logger.info(f"NVD sync: {start}/{total_results} — {inserted} entries inserted")
        time.sleep(REQ_DELAY)
    new_last_mod = time.strftime("%Y-%m-%dT%H:%M:%S.000", time.gmtime())
    db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('last_mod', ?)", (new_last_mod,))
    db.commit()
    db.execute("ANALYZE")
    db.close()
    from depwolf.infrastructure.index_sync import write_manifest

    try:
        write_manifest(DB_PATH)
    except Exception as e:
        logger.warning(f"manifest write failed (index still valid): {e}")
    logger.info(f"NVD sync complete. {inserted} total entries inserted.")


def verify_index(db_path: Path = DB_PATH) -> tuple[bool, str]:
    """Verify a local index's manifest/checksum/signature (P2-1)."""
    from depwolf.infrastructure.index_sync import verify_index as _verify

    return _verify(Path(db_path))


def index_stats(db_path: Path = DB_PATH) -> dict:
    """Lightweight stats for `depwolf db`."""
    p = Path(db_path)
    if not p.exists():
        return {"exists": False}
    stats: dict = {
        "exists": True,
        "bytes": p.stat().st_size,
        "rows": 0,
        "last_mod": None,
    }
    try:
        conn = sqlite3.connect(str(p))
        stats["rows"] = conn.execute("SELECT COUNT(*) FROM cpe_index").fetchone()[0]
        row = conn.execute("SELECT value FROM meta WHERE key='last_mod'").fetchone()
        stats["last_mod"] = row[0] if row else None
        conn.close()
    except Exception:
        pass
    return stats


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    import sys

    full = "--full" in sys.argv
    build_index(full_sync=full)
