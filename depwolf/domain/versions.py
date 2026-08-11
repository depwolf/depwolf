"""Shared version engine (ADR-005).

Single implementation of CPE normalization, version tokenization, and
version-range checks. Moved here from ``cpe_index`` so the matcher, the
remediation layer, and (later) SBOM/policy tooling all agree on ordering.
"""

import re


def _normalize(s: str) -> str:
    s = s.lower().strip()
    s = re.sub(r"[^a-z0-9.+-]", "", s)
    return s


def _parse_cpe23(cpe_str: str) -> dict | None:
    parts = cpe_str.split(":")
    if len(parts) < 6:
        return None
    vendor = parts[3] if parts[3] != "*" else None
    product = parts[4] if parts[4] != "*" else None
    version = parts[5] if parts[5] not in ("*", "-") else None
    if not vendor or not product:
        return None
    return {"vendor": _normalize(vendor), "product": _normalize(product), "version": version}


def _version_key(v: str) -> tuple:
    """Normalize any version string into a sortable token tuple.

    Handles Debian epochs ("1:9.2p1-2+deb12u5"), OpenSSL letter suffixes
    ("1.0.1e" < "1.0.1g"), and plain dotted numerics ("8.6"). A trailing
    letter sorts above the bare numeric ("1.0.1e" > "1.0.1") but below the
    next numeric step ("1.0.1e" < "1.0.2"), matching NVD's semantics.
    """
    v = v.strip().lower()
    epoch = 0
    m = re.match(r"^[0-9]+:", v)
    if m:
        epoch = int(m.group(0)[:-1])
        v = v[m.end() :]
    toks = []
    for part in re.split(r"[^a-z0-9]+", v):
        if not part:
            continue
        for seg in re.findall(r"[0-9]+|[a-z]+", part):
            if seg.isdigit():
                toks.append(int(seg))
            else:
                toks.append(0)
                toks.extend(ord(ch) - 96 for ch in seg)
    return (epoch, *toks)


def _version_in_range(version: str, start_incl, start_excl, end_incl, end_excl) -> bool:
    v = _version_key(version)
    if start_incl and v < _version_key(start_incl):
        return False
    if start_excl and v <= _version_key(start_excl):
        return False
    if end_incl and v > _version_key(end_incl):
        return False
    if end_excl and v >= _version_key(end_excl):
        return False
    return True
