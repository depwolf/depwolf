"""Component identity (Phase 1, spec §2/§13/§15/§16).

A unified ``Component`` ties together the many names a package can carry across
scanners and the CVE index: purl, ecosystem/type, namespace, and the CPE vendor
+ product that NVD actually indexes. The resolver uses this when the package
name alone would miss the index row (e.g. ``torch`` -> ``pytorch``,
``tensorflow-cpu`` -> ``tensorflow``), which is the exact false-negative class
that raw name matching hits for AI/ML and aliased packages.

This module is pure/self-contained: no DB, no I/O, no imports from the rest of
depwolf, so it is trivially testable and safe to reuse in matcher, adapter, and
SBOM paths.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Purl:
    """A parsed Package URL (https://github.com/package-url/purl-spec)."""

    type: str
    name: str
    version: str | None = None
    namespace: str | None = None
    qualifiers: dict[str, str] = field(default_factory=dict)
    subpath: str | None = None

    @property
    def key(self) -> str:
        return f"{self.type}:{self.name}"


def parse_purl(purl: str | None) -> Purl | None:
    """Parse a Package URL string into a ``Purl`` (or None when malformed)."""
    if not purl or not isinstance(purl, str) or not purl.strip().startswith("pkg:"):
        return None
    rest = purl[len("pkg:") :].strip()
    if not rest:
        return None

    subpath = None
    if "#" in rest:
        rest, _, subpath = rest.partition("#")
        subpath = subpath or None

    qualifiers: dict[str, str] = {}
    if "?" in rest:
        rest, _, qs = rest.partition("?")
        for pair in qs.split("&"):
            if "=" in pair:
                k, _, v = pair.partition("=")
                if k:
                    qualifiers[k] = v

    version = None
    if "@" in rest:
        rest, _, version = rest.rpartition("@")
        version = version or None

    segs = [s for s in rest.split("/") if s]
    if len(segs) < 2:
        return None
    ptype = segs[0].lower()
    namespace = segs[1].lower() if len(segs) >= 3 else None
    name = (segs[2] if len(segs) >= 3 else segs[1]).lower()
    if not ptype or not name:
        return None
    return Purl(type=ptype, name=name, version=version, namespace=namespace, qualifiers=qualifiers, subpath=subpath)


@dataclass(frozen=True)
class Component:
    """A package as identified across purl and CPE ecosystems."""

    name: str
    version: str | None
    ecosystem: str | None  # purl type (pypi / npm / deb / ...), when known
    namespace: str | None
    purl: str
    vendor: str | None  # CPE vendor hint, when curated
    product: str | None  # CPE product hint, when curated

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}" if self.ecosystem else self.name


# Curated purl -> (cpe vendor, cpe product) for packages whose NVD CPE product
# is not the package name. Resolution runs as a PRODUCT prefix search, so the
# product hint is what matters; the vendor hint is kept for display/evidence.
# Keeping this table tiny and AI-focused; language-ecosystem aliases land with
# the per-ecosystem engines (Phase 4).
PURL_CPE_HINTS: dict[str, tuple[str | None, str]] = {
    # AI / ML frameworks
    "pypi:torch": ("pytorch", "pytorch"),
    "pypi:torchvision": ("pytorch", "torchvision"),
    "pypi:torchaudio": ("pytorch", "torchaudio"),
    "pypi:tensorflow": ("google", "tensorflow"),
    "pypi:tensorflow-cpu": ("google", "tensorflow"),
    "pypi:tensorflow-gpu": ("google", "tensorflow"),
    "pypi:tensorflow-estimator": ("google", "tensorflow-estimator"),
    "pypi:onnx": ("onnx", "onnx"),
    "pypi:onnxruntime": ("microsoft", "onnxruntime"),
    "pypi:ort": ("microsoft", "onnxruntime"),
    "pypi:scikit-learn": ("scikit-learn", "scikit-learn"),
    "pypi:sklearn": ("scikit-learn", "scikit-learn"),
    "pypi:keras": ("keras", "keras"),
    "pypi:transformers": ("huggingface", "transformers"),
    "pypi:huggingface-hub": ("huggingface", "huggingface-hub"),
    "pypi:langchain": ("langchain", "langchain"),
    "pypi:llama-index": ("llama-index", "llama-index"),
}


# Debian binary package -> (cpe vendor, upstream CPE product). NVD indexes
# Debian packages under the upstream project name (util-linux, systemd, acl,
# ncurses) while scanners report the Debian binary name (libmount1, libsystemd0,
# libacl1, libncursesw6). Without the alias, the stack product never finds the
# index row — the not_in_stack FP that Phase 1 exists to kill.
DEB_LIBRARY_HINTS: dict[str, tuple[str | None, str]] = {
    "util-linux": ("util-linux", "util-linux"),
    "bsdutils": ("util-linux", "util-linux"),
    "login": ("util-linux", "util-linux"),
    "mount": ("util-linux", "util-linux"),
    "libmount1": ("util-linux", "util-linux"),
    "libblkid1": ("util-linux", "util-linux"),
    "libuuid1": ("util-linux", "util-linux"),
    "libsmartcols1": ("util-linux", "util-linux"),
    "liblastlog2-2": ("util-linux", "util-linux"),
    "libfdisk1": ("util-linux", "util-linux"),
    "systemd": ("freedesktop", "systemd"),
    "libsystemd0": ("freedesktop", "systemd"),
    "libudev1": ("freedesktop", "systemd"),
    "acl": ("acl", "acl"),
    "libacl1": ("acl", "acl"),
    "libncursesw6": ("invisible-island", "ncurses"),
    "libtinfo6": ("invisible-island", "ncurses"),
    "ncurses-base": ("invisible-island", "ncurses"),
    "ncurses-bin": ("invisible-island", "ncurses"),
    "perl-base": ("archive", "perl"),
    "libssl3": ("openssl", "openssl"),
    "libsemanage1": ("selinuxproject", "libsemanage"),
    "libcap2": ("kernel", "libcap"),
}


def component_from_purl(purl: str | None) -> Component | None:
    """Build a ``Component`` from a purl, attaching curated CPE hints when known."""
    if not purl:
        return None
    p = parse_purl(purl)
    if p is None:
        return None
    vendor, product = PURL_CPE_HINTS.get(p.key, (None, None))
    if product is None and p.type == "deb":
        vendor, product = DEB_LIBRARY_HINTS.get(p.name, (None, None))
    return Component(
        name=p.name,
        version=p.version,
        ecosystem=p.type,
        namespace=p.namespace,
        purl=purl,
        vendor=vendor,
        product=product,
    )