"""Pure product/version matching rules (ADR-005, ADR-014).

These functions are deterministic and side-effect free so they are trivially
unit-testable and shared by the repository (product resolution), the funnel
filters (asset matching), and the native scanner.
"""

from __future__ import annotations

import re

from depwolf.domain.model import Asset, VulnRange
from depwolf.domain.versions import _normalize, _version_in_range

_PRODUCT_ALIASES = {
    "apachehttpd": "httpserver",
    "apachehttpserver": "httpserver",
    "httpd": "httpserver",
    "nodejs": "node.js",
    "postgres": "postgresql",
    "mysqlserver": "mysql",
    "mongo": "mongodb",
    "apachetomcat": "tomcat",
    "curl": "libcurl",
}

_PACKAGING_SUFFIXES = ("server", "client", "runtime", "sdk", "lib", "library", "core", "api", "common", "base")


def _compact(s: str) -> str:
    return re.sub(r"[^a-z0-9.+]", "", s.lower())


_CONF_ORDER = {"exact": 4, "alias": 3, "canonical": 3, "fuzzy": 2, "heuristic": 1}

MATCH_CONFIDENCE_LEVELS = ("exact", "alias", "canonical", "fuzzy", "heuristic")


def product_match_confidence(norm: str, row_product: str) -> str | None:
    """Classify how a stack product matches an index product.

    Returns exact / alias / canonical / fuzzy, or None when they do not match.
    exact and alias are high-confidence; canonical (packaging suffix) is
    high-confidence; a bare digit-prefix match is only fuzzy (medium).
    """
    a = _compact(norm)
    b = _compact(row_product)
    if not a or not b:
        return None
    if a == b:
        return "exact"
    if _PRODUCT_ALIASES.get(a) == b or _PRODUCT_ALIASES.get(b) == a:
        return "alias"
    short, long = (a, b) if len(a) <= len(b) else (b, a)
    if long.startswith(short):
        rest = long[len(short) :]
        if rest in _PACKAGING_SUFFIXES:
            return "canonical"
        if rest.isdigit():
            return "fuzzy"
    return None


def better_confidence(a: str | None, b: str) -> str:
    """Return the higher of two match-confidence levels."""
    if a is None:
        return b
    return a if _CONF_ORDER.get(a, 0) >= _CONF_ORDER.get(b, 0) else b


def fuzzy_product_match(norm: str, row_product: str) -> bool:
    """Fuzzy match a normalized stack product against a CPE product name."""
    return product_match_confidence(norm, row_product) is not None


def asset_matches(asset: Asset, row: VulnRange) -> bool:
    """Does a stack asset fall inside this vulnerable version range?"""
    norm = _normalize(asset.product)
    if not fuzzy_product_match(norm, row.product):
        return False
    if asset.version and not _version_in_range(
        asset.version,
        row.version_start_including,
        row.version_start_excluding,
        row.version_end_including,
        row.version_end_excluding,
    ):
        return False
    return True


def row_os(row: VulnRange) -> str | None:
    """Best-effort OS family for a range row (linux / windows / None)."""
    vendor = (row.vendor or "").lower()
    product = (row.product or "").lower()
    if vendor in ("microsoft", "mswin") and (
        product.startswith("windows")
        or product
        in (
            "iis",
            "activedirectory",
            "exchangeserver",
            "sharepoint",
            "sqlserver",
            "visualstudio",
            "internetexplorer",
            "edge",
            "office",
        )
    ):
        return "windows"
    if product == "linuxkernel" or vendor in (
        "linux",
        "canonical",
        "debian",
        "fedoraproject",
        "redhat",
        "suse",
        "almalinux",
        "amazon",
        "rockylinux",
        "opensuse",
        "centos",
        "kali",
        "ubuntu",
        "archlinux",
    ):
        return "linux"
    return None
