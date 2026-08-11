"""Compatibility shim — real code lives in depwolf.application.scanner."""

from depwolf.application.scanner import (  # noqa: F401
    collect_project,
    deps_to_stack,
    find_manifests,
    parse_manifests,
    scan_project,
)
