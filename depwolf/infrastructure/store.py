"""Sqlite-backed implementation of the CVERepository port (ADR-003, ADR-017).

The repository owns connection lifecycle and returns typed domain objects
(``VulnRange``, ``ProductMatch``). ``open()``/``close()`` are retained as
low-level helpers for seeding; application code uses the repository methods and
never sees ``sqlite3``.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from depwolf.domain.match import _PRODUCT_ALIASES, _compact, fuzzy_product_match, product_match_confidence
from depwolf.domain.model import ProductMatch, VulnRange
from depwolf.domain.versions import _normalize
from depwolf.infrastructure.cpe_index import DB_PATH, _ensure_schema

IGNORED_TABLE = """
CREATE TABLE IF NOT EXISTS ignored_cves (
    cve_id TEXT PRIMARY KEY,
    ignored_at TEXT
)
"""


class SqliteIndexStore:
    """Default store backed by a cpe_index.db on disk (or a shared in-memory DB)."""

    def __init__(self, path: str | Path | None = None, *, memory: bool = False):
        self._path = Path(path) if path is not None else DB_PATH
        self._memory = memory
        self._shared: sqlite3.Connection | None = None
        self._opens = 0

    @property
    def path(self) -> Path:
        return self._path

    @property
    def open_count(self) -> int:
        """Number of connections opened since construction (test seam)."""
        return self._opens

    def open(self) -> sqlite3.Connection:
        if self._memory:
            if self._shared is None:
                self._shared = sqlite3.connect(":memory:")
                self._shared.row_factory = sqlite3.Row
                _ensure_schema(self._shared)
            return self._shared
        self._opens += 1
        conn = sqlite3.connect(str(self._path))
        conn.row_factory = sqlite3.Row
        return conn

    def close(self, conn: sqlite3.Connection) -> None:
        if not self._memory:
            conn.close()

    # ---- repository API -------------------------------------------------

    def cve(self, cve_id: str) -> list[VulnRange]:
        db = self.open()
        try:
            rows = db.execute("SELECT * FROM cpe_index WHERE cve_id=?", (cve_id.upper(),)).fetchall()
            return [_row_to_range(r) for r in rows]
        finally:
            self.close(db)

    def cves_for_product(self, vendor: str, product: str) -> list[VulnRange]:
        return self.cves_for_products([(vendor, product)]).get((vendor, product), [])

    def cve_ids_for_product(self, vendor: str, product: str) -> list[str]:
        return [r.cve_id for r in self.cves_for_product(vendor, product)]

    def resolve_products(self, name: str, limit: int = 25) -> list[ProductMatch]:
        return self.resolve_products_many([name], limit=limit).get(name, [])

    def resolve_products_many(self, names: list[str], limit: int = 25) -> dict[str, list[ProductMatch]]:
        """Resolve many stack product names on ONE connection.

        Mirrors the original ``_find_cpe_products`` per-name semantics: prefix
        search with an exact compact match short-circuit, alias fallback, then
        fuzzy filtering — but a single connection serves the whole batch.
        """
        out: dict[str, list[ProductMatch]] = {}
        normed: dict[str, str] = {}
        for name in names:
            norm = _normalize(name)
            if norm:
                normed.setdefault(norm, name)
        if not normed:
            return out
        db = self.open()
        try:
            for norm, orig in normed.items():
                out[orig] = self._resolve_one(db, norm, limit)
            return out
        finally:
            self.close(db)

    def _resolve_one(self, db: sqlite3.Connection, norm: str, limit: int) -> list[ProductMatch]:
        candidates: list[sqlite3.Row] = []
        for i in range(len(norm), 0, -1):
            prefix = norm[:i]
            rows = db.execute(
                "SELECT DISTINCT vendor, product FROM cpe_index WHERE product LIKE ? LIMIT ?",
                (f"{prefix}%", limit),
            ).fetchall()
            for r in rows:
                if _compact(r["product"]) == _compact(norm):
                    return [ProductMatch(vendor=r["vendor"], product=r["product"], confidence="exact")]
            if rows:
                candidates.extend(rows)
                break
        alias = _PRODUCT_ALIASES.get(_compact(norm))
        if alias:
            rows = db.execute(
                "SELECT DISTINCT vendor, product FROM cpe_index WHERE product = ? LIMIT ?",
                (alias, limit),
            ).fetchall()
            if rows:
                return [ProductMatch(vendor=rows[0]["vendor"], product=rows[0]["product"], confidence="alias")]
        seen: set[tuple[str, str]] = set()
        out: list[ProductMatch] = []
        for r in candidates:
            if not fuzzy_product_match(norm, r["product"]):
                continue
            key = (r["vendor"], r["product"])
            if key not in seen:
                seen.add(key)
                out.append(
                    ProductMatch(
                        vendor=r["vendor"],
                        product=r["product"],
                        confidence=product_match_confidence(norm, r["product"]) or "fuzzy",
                    )
                )
        return out

    def cves_for_products(self, products: list[tuple[str, str]]) -> dict[tuple[str, str], list[VulnRange]]:
        """Fetch ranges for many (vendor, product) pairs on ONE connection.

        Uses a single prepared ``OR`` statement, so a 200-dep stack is one
        round-trip instead of one connection + one LIKE per dependency.
        """
        unique = list(dict.fromkeys(products))
        if not unique:
            return {}
        clause = " OR ".join(["(vendor=? AND product=?)"] * len(unique))
        params: list[str] = []
        for vendor, product in unique:
            params.extend([vendor, product])
        db = self.open()
        try:
            rows = db.execute(
                f"SELECT * FROM cpe_index WHERE {clause}",
                params,
            ).fetchall()
        finally:
            self.close(db)
        out: dict[tuple[str, str], list[VulnRange]] = {p: [] for p in unique}
        for r in rows:
            key = (r["vendor"], r["product"])
            out.setdefault(key, []).append(_row_to_range(r))
        return out

    def cves_for_ids(self, cve_ids: list[str]) -> dict[str, list[VulnRange]]:
        """Fetch all ranges for many CVE IDs on ONE connection (prepared IN)."""
        ids = list(dict.fromkeys(str(c).strip().upper() for c in cve_ids))
        ids = [i for i in ids if i]
        if not ids:
            return {}
        placeholders = ",".join("?" * len(ids))
        db = self.open()
        try:
            rows = db.execute(
                f"SELECT * FROM cpe_index WHERE cve_id IN ({placeholders})",
                ids,
            ).fetchall()
        finally:
            self.close(db)
        out: dict[str, list[VulnRange]] = {i: [] for i in ids}
        for r in rows:
            out.setdefault(r["cve_id"], []).append(_row_to_range(r))
        return out

    def ignored(self, cve_ids: set[str]) -> set[str]:
        if not cve_ids:
            return set()
        db = self.open()
        try:
            self._ensure_ignored(db)
            placeholders = ",".join("?" * len(cve_ids))
            rows = db.execute(
                f"SELECT cve_id FROM ignored_cves WHERE cve_id IN ({placeholders})",
                tuple(cve_ids),
            ).fetchall()
            return {r[0] for r in rows}
        finally:
            self.close(db)

    def all_ignored(self) -> set[str]:
        db = self.open()
        try:
            self._ensure_ignored(db)
            rows = db.execute("SELECT cve_id FROM ignored_cves").fetchall()
            return {r[0] for r in rows}
        finally:
            self.close(db)

    def ignore(self, cve_id: str) -> None:
        db = self.open()
        try:
            self._ensure_ignored(db)
            db.execute(
                "INSERT OR IGNORE INTO ignored_cves (cve_id, ignored_at) VALUES (?, ?)",
                (cve_id, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
            )
            db.commit()
        finally:
            self.close(db)

    def unignore(self, cve_id: str) -> None:
        db = self.open()
        try:
            self._ensure_ignored(db)
            db.execute("DELETE FROM ignored_cves WHERE cve_id=?", (cve_id,))
            db.commit()
        finally:
            self.close(db)

    @staticmethod
    def _ensure_ignored(db: sqlite3.Connection) -> None:
        db.execute(IGNORED_TABLE)
        db.commit()


def _row_to_range(r) -> VulnRange:
    return VulnRange(
        cve_id=r["cve_id"],
        vendor=r["vendor"],
        product=r["product"],
        version_start_including=r["version_start_including"],
        version_start_excluding=r["version_start_excluding"],
        version_end_including=r["version_end_including"],
        version_end_excluding=r["version_end_excluding"],
        description=r["description"] or "",
        cvss_score=r["cvss_score"] or 0.0,
        cvss_severity=r["cvss_severity"] or "",
        epss_score=r["epss_score"] or 0.0,
        kev=bool(r["kev"]),
        published_date=r["published_date"],
    )
