"""Compatibility shim — real code lives in depwolf.infrastructure.cpe_index.

Version/CPE helpers moved to depwolf.domain.versions. Importing this module
keeps old ``from depwolf.cpe_index import ...`` call sites working.
"""

from depwolf.domain.versions import _normalize, _parse_cpe23, _version_in_range, _version_key  # noqa: F401
from depwolf.infrastructure.cpe_index import (  # noqa: F401
    DB_PATH,
    EPSS_API,
    KEV_URL,
    NVD_API_KEY,
    NVD_BASE,
    REQ_DELAY,
    RESULTS_PER_PAGE,
    _ensure_schema,
    _fetch_epss,
    _fetch_kev,
    _init_db,
    build_index,
    download_index,
    fetch_nvd_page,
    index_stats,
    verify_index,
)
