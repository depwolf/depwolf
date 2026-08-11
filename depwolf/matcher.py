"""Compatibility shim — real code lives in depwolf.application.matcher."""

from depwolf.application.matcher import (  # noqa: F401
    candidates_for_stack,
    check_cve,
    extract_os,
    get_ignored_cves,
    ignore_cve,
    ingest_trivy,
    match_stack,
    parse_stack,
    prioritize_cves,
    unignore_cve,
)
