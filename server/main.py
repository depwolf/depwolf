"""depwolf CVE index API — FastAPI query service for the cloud backend.

Serves the local ``cpe_index.db`` over HTTP so the CLI can run in cloud API
mode (``AVIP_API_URL``) without downloading the 1.5 GB index.  All queries go
through the same ``SqliteIndexStore`` / ``CVERepository`` port that the CLI
uses locally.

Endpoints mirror ``depwolf/infrastructure/api_client.py``:

    GET    /api/cve/{cve_id}        -> list[VulnRange]
    POST   /api/cves/by-ids         -> {cve_id: [VulnRange]}
    POST   /api/cves/by-products    -> {"vendor|product": [VulnRange]}
    POST   /api/resolve-products    -> {name: [ProductMatch]}
    GET    /api/ignored             -> {"ignored": [...]}
    POST   /api/ignore              -> ignore a CVE
    DELETE /api/ignore/{cve_id}     -> unignore a CVE
    GET    /healthz                 -> liveness
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(title="depwolf CVE index", version="0.1.0")

DB_ENV = "AVIP_DB_PATH"
API_KEY_ENV = "AVIP_SERVER_API_KEY"
DEFAULT_DB = str(Path.home() / ".depwolf" / "cpe_index.db")


class IgnoreRequest(BaseModel):
    cve_id: str


def _db_path() -> str:
    return os.environ.get(DB_ENV) or DEFAULT_DB


def _verified_required() -> bool:
    return bool(os.environ.get(API_KEY_ENV))


def _api_key(request: Request) -> str | None:
    return request.headers.get("X-API-Key")


def require_key(request: Request) -> None:
    """Optional bearer override: reject requests without the correct API key."""
    if not _verified_required():
        return
    expected = os.environ.get(API_KEY_ENV, "")
    if _api_key(request) != expected:
        raise HTTPException(status_code=401, detail="invalid or missing API key")


def store():
    from depwolf.infrastructure.store import SqliteIndexStore

    return SqliteIndexStore(os.environ.get(DB_ENV) or DEFAULT_DB)


def _vuln_range(r) -> dict[str, Any]:
    return {
        "cve_id": r.cve_id,
        "vendor": r.vendor,
        "product": r.product,
        "version_start_including": r.version_start_including,
        "version_start_excluding": r.version_start_excluding,
        "version_end_including": r.version_end_including,
        "version_end_excluding": r.version_end_excluding,
        "description": r.description,
        "cvss_score": r.cvss_score,
        "cvss_severity": r.cvss_severity,
        "epss_score": r.epss_score,
        "kev": r.kev,
        "published_date": r.published_date,
    }


def _product_match(m) -> dict[str, Any]:
    return {"vendor": m.vendor, "product": m.product, "confidence": m.confidence}


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    path = _db_path()
    if not Path(path).exists():
        return JSONResponse(status_code=503, content={"status": "unhealthy", "reason": f"no index at {path}"})
    return {"status": "healthy", "db": path}


@app.get("/api/cve/{cve_id}", dependencies=[Depends(require_key)])
def get_cve(cve_id: str) -> list[dict[str, Any]]:
    return [_vuln_range(r) for r in store().cve(cve_id)]


class ByIdsRequest(BaseModel):
    cve_ids: list[str]


@app.post("/api/cves/by-ids", dependencies=[Depends(require_key)])
def cves_by_ids(req: ByIdsRequest) -> dict[str, list[dict[str, Any]]]:
    data = store().cves_for_ids(req.cve_ids)
    return {cid: [_vuln_range(r) for r in ranges] for cid, ranges in data.items()}


class ProductPair(BaseModel):
    vendor: str
    product: str


@app.post("/api/cves/by-products", dependencies=[Depends(require_key)])
def cves_by_products(req: list[ProductPair]) -> dict[str, list[dict[str, Any]]]:
    pairs = [(p.vendor, p.product) for p in req]
    data = store().cves_for_products(pairs)
    return {f"{v}|{p}": [_vuln_range(r) for r in ranges] for (v, p), ranges in data.items()}


class ResolveRequest(BaseModel):
    names: list[str]
    limit: int = 25


@app.post("/api/resolve-products", dependencies=[Depends(require_key)])
def resolve_products(req: ResolveRequest) -> dict[str, list[dict[str, Any]]]:
    data = store().resolve_products_many(req.names, limit=req.limit)
    return {name: [_product_match(m) for m in matches] for name, matches in data.items()}


@app.get("/api/ignored", dependencies=[Depends(require_key)])
def list_ignored() -> dict[str, list[str]]:
    return {"ignored": sorted(store().all_ignored())}


@app.post("/api/ignore", dependencies=[Depends(require_key)])
def add_ignore(req: IgnoreRequest) -> dict[str, str]:
    store().ignore(req.cve_id)
    return {"status": "ignored", "cve_id": req.cve_id.upper()}


@app.delete("/api/ignore/{cve_id}", dependencies=[Depends(require_key)])
def remove_ignore(cve_id: str) -> dict[str, str]:
    store().unignore(cve_id)
    return {"status": "unignored", "cve_id": cve_id.upper()}