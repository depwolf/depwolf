"""HTTP-backed implementation of the CVERepository port for cloud API mode.

When ``AVIP_API_URL`` is set, depwolf queries the remote FastAPI endpoint
on-demand instead of using a local SQLite index.  This avoids the 1.5 GB
download while still providing full CVE lookup, product resolution, and
ignore-list management.

Expected FastAPI endpoints (to be implemented on Oracle Cloud):

    GET  /api/cve/{cve_id}           -> list[VulnRange]
    GET  /api/cves                   -> list[VulnRange]  (batch, POST with IDs)
    POST /api/cves/by-ids            -> {cve_id: [VulnRange]}
    POST /api/cves/by-products       -> {(vendor,product): [VulnRange]}
    POST /api/resolve-products       -> {name: [ProductMatch]}
    GET  /api/ignored                -> set[str]
    POST /api/ignore                 -> {"cve_id": ..., "ignored_at": ...}
    DELETE /api/ignore/{cve_id}      -> ok
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from depwolf.domain.model import ProductMatch, VulnRange

_API_URL_ENV = "AVIP_API_URL"
_DEFAULT_TIMEOUT = 30


class ApiClientRepository:
    """CVERepository implementation that queries a remote FastAPI endpoint."""

    def __init__(self, base_url: str | None = None, *, timeout: int = _DEFAULT_TIMEOUT):
        raw = base_url or os.environ.get(_API_URL_ENV, "")
        self._base = raw.rstrip("/")
        self._timeout = timeout
        self._ignored_cache: set[str] | None = None
        self._ignored_cache_ts: float = 0.0

    # ---- helpers -----------------------------------------------------------

    @property
    def path(self) -> Path:
        return Path(f"[api:{self._base}]")

    def _get(self, endpoint: str) -> Any:
        url = f"{self._base}{endpoint}"
        req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "depwolf/1.0"})
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            return json.loads(resp.read())

    def _post(self, endpoint: str, payload: dict | list) -> Any:
        url = f"{self._base}{endpoint}"
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "depwolf/1.0"},
        )
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            return json.loads(resp.read())

    def _delete(self, endpoint: str) -> Any:
        url = f"{self._base}{endpoint}"
        req = urllib.request.Request(url, method="DELETE", headers={"User-Agent": "depwolf/1.0"})
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            return json.loads(resp.read()) if resp.read() else None

    # ---- repository API ----------------------------------------------------

    def cve(self, cve_id: str) -> list[VulnRange]:
        try:
            data = self._get(f"/api/cve/{cve_id.upper()}")
            return [_dict_to_vuln_range(r) for r in data]
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return []
            raise

    def cves_for_product(self, vendor: str, product: str) -> list[VulnRange]:
        return self.cves_for_products([(vendor, product)]).get((vendor, product), [])

    def cve_ids_for_product(self, vendor: str, product: str) -> list[str]:
        return [r.cve_id for r in self.cves_for_product(vendor, product)]

    def resolve_products(self, name: str, limit: int = 25) -> list[ProductMatch]:
        return self.resolve_products_many([name], limit=limit).get(name, [])

    def resolve_products_many(self, names: list[str], limit: int = 25) -> dict[str, list[ProductMatch]]:
        if not names:
            return {}
        try:
            data = self._post("/api/resolve-products", {"names": names, "limit": limit})
            return {
                name: [_dict_to_product_match(m) for m in matches]
                for name, matches in data.items()
            }
        except Exception:
            return {name: [] for name in names}

    def cves_for_products(self, products: list[tuple[str, str]]) -> dict[tuple[str, str], list[VulnRange]]:
        if not products:
            return {}
        unique = list(dict.fromkeys(products))
        payload = [{"vendor": v, "product": p} for v, p in unique]
        try:
            data = self._post("/api/cves/by-products", payload)
            result: dict[tuple[str, str], list[VulnRange]] = {p: [] for p in unique}
            for key_str, ranges in data.items():
                key = tuple(key_str.split("|", 1))
                if len(key) == 2 and key in result:
                    result[key] = [_dict_to_vuln_range(r) for r in ranges]
            return result
        except Exception:
            return {p: [] for p in unique}

    def cves_for_ids(self, cve_ids: list[str]) -> dict[str, list[VulnRange]]:
        ids = list(dict.fromkeys(str(c).strip().upper() for c in cve_ids))
        ids = [i for i in ids if i]
        if not ids:
            return {}
        try:
            data = self._post("/api/cves/by-ids", {"cve_ids": ids})
            return {cve_id: [_dict_to_vuln_range(r) for r in ranges] for cve_id, ranges in data.items()}
        except Exception:
            return {i: [] for i in ids}

    def ignored(self, cve_ids: set[str]) -> set[str]:
        if not cve_ids:
            return set()
        all_ignored = self.all_ignored()
        return cve_ids & all_ignored

    def all_ignored(self) -> set[str]:
        now = time.time()
        if self._ignored_cache is not None and (now - self._ignored_cache_ts) < 60:
            return self._ignored_cache
        try:
            data = self._get("/api/ignored")
            self._ignored_cache = set(data.get("ignored", []))
            self._ignored_cache_ts = now
            return self._ignored_cache
        except Exception:
            return set()

    def ignore(self, cve_id: str) -> None:
        try:
            self._post("/api/ignore", {"cve_id": cve_id.upper()})
            self._ignored_cache = None
        except Exception:
            pass

    def unignore(self, cve_id: str) -> None:
        try:
            self._delete(f"/api/ignore/{cve_id.upper()}")
            self._ignored_cache = None
        except Exception:
            pass


def _dict_to_vuln_range(d: dict[str, Any]) -> VulnRange:
    return VulnRange(
        cve_id=d.get("cve_id", ""),
        vendor=d.get("vendor", ""),
        product=d.get("product", ""),
        version_start_including=d.get("version_start_including"),
        version_start_excluding=d.get("version_start_excluding"),
        version_end_including=d.get("version_end_including"),
        version_end_excluding=d.get("version_end_excluding"),
        description=d.get("description", ""),
        cvss_score=float(d.get("cvss_score", 0.0)),
        cvss_severity=d.get("cvss_severity", ""),
        epss_score=float(d.get("epss_score", 0.0)),
        kev=bool(d.get("kev", False)),
        published_date=d.get("published_date"),
    )


def _dict_to_product_match(d: dict[str, Any]) -> ProductMatch:
    return ProductMatch(
        vendor=d.get("vendor", ""),
        product=d.get("product", ""),
        confidence=d.get("confidence", "fuzzy"),
    )
