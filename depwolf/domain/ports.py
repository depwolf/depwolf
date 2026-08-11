"""Ports (interfaces) owned by the domain that infrastructure implements.

The domain depends only on these protocols — never on ``sqlite3``, files, or
HTTP. Implementations own their connection lifecycle; callers receive typed
objects (``VulnRange``, ``ProductMatch``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from depwolf.domain.model import ProductMatch, VulnRange


class CVERepository(Protocol):
    """How the application reads and writes the CVE index and ignore list.

    No connections or SQL leak across this boundary: every method returns
    typed domain objects.
    """

    @property
    def path(self) -> Path: ...

    def cve(self, cve_id: str) -> list[VulnRange]: ...
    def cves_for_product(self, vendor: str, product: str) -> list[VulnRange]: ...
    def cve_ids_for_product(self, vendor: str, product: str) -> list[str]: ...
    def resolve_products(self, name: str, limit: int = 25) -> list[ProductMatch]: ...

    # Batch access (Phase 3): let the matcher resolve a whole stack and match
    # every CVE in ONE connection pass instead of connection-per-call.
    def resolve_products_many(self, names: list[str], limit: int = 25) -> dict[str, list[ProductMatch]]: ...
    def cves_for_products(self, products: list[tuple[str, str]]) -> dict[tuple[str, str], list[VulnRange]]: ...
    def cves_for_ids(self, cve_ids: list[str]) -> dict[str, list[VulnRange]]: ...

    def ignored(self, cve_ids: set[str]) -> set[str]: ...
    def all_ignored(self) -> set[str]: ...
    def ignore(self, cve_id: str) -> None: ...
    def unignore(self, cve_id: str) -> None: ...
