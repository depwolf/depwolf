from hypothesis import given
from hypothesis import strategies as st

from depwolf.domain.versions import _version_in_range, _version_key


def _mk(v: str) -> tuple:
    return _version_key(v)


@st.composite
def _version(draw):
    parts = draw(st.lists(st.integers(min_value=0, max_value=99), min_size=1, max_size=4))
    base = ".".join(str(p) for p in parts)
    epoch = draw(st.one_of(st.none(), st.integers(min_value=0, max_value=9)))
    suffix = draw(st.one_of(st.none(), st.sampled_from("abceghpr")))
    out = ""
    if epoch is not None:
        out += f"{epoch}:"
    out += base
    if suffix:
        out += suffix
    return out


def test_reflexive():
    assert _version_key("1.2.3") == _version_key("1.2.3")
    assert _version_key("1:9.2p1-2") == _version_key("1:9.2p1-2")


def test_transitive():
    a, b, c = "1.0", "1.1", "1.2"
    assert _mk(a) < _mk(b) < _mk(c)
    assert _mk(a) < _mk(c)


def test_total_order():
    vs = ["0.9", "1.0", "1.0.1", "1.0.1e", "1.0.1g", "1.0.2", "1.1", "2.0"]
    keys = [_mk(v) for v in vs]
    assert keys == sorted(keys)
    assert len(set(keys)) == len(keys)


def test_epochs_beat_non_epoch():
    assert _mk("1:0.1") > _mk("9.9.9")
    assert _mk("1:1.0") < _mk("2:0.1")


def test_letter_suffix_between_steps():
    assert _mk("1.0.1") < _mk("1.0.1e") < _mk("1.0.1g") < _mk("1.0.2")


@given(_version())
def test_normalized_versions_are_consistent(v):
    key = _mk(v)
    assert isinstance(key, tuple)
    assert all(isinstance(t, int) and t >= 0 for t in key)


@given(v=st.sampled_from(["8.6", "1.0.1e", "1:9.2p1-2+deb12u5", "0.0.1", "2.15.0", "1.2.3-alpha"]))
def test_remediation_uses_shared_engine(v):
    from depwolf.application.remediation import _bump_version

    assert _mk(v) == _mk(v)
    bumped = _bump_version(v)
    assert _mk(bumped) >= _mk(v)


def test_nvd_real_world_examples():
    assert _version_in_range("1.0.1e", None, None, None, "1.0.2")
    assert not _version_in_range("1.0.2", None, None, None, "1.0.2")
    assert _version_in_range("2.0", "2.0", None, None, "2.15.0")
    assert not _version_in_range("2.15.0", "2.0", None, None, "2.15.0")
    assert _version_in_range("1.8", "1.0", None, None, "1.9")


def test_inclusive_start_boundary():
    assert _version_in_range("2.0", "2.0", None, None, "2.15.0")
    assert not _version_in_range("1.9.9", "2.0", None, None, "2.15.0")


def test_exclusive_start_boundary():
    assert _version_in_range("2.0.1", None, "2.0", None, "2.15.0")
    assert not _version_in_range("2.0", None, "2.0", None, "2.15.0")


def test_inclusive_end_boundary():
    assert _version_in_range("2.15.0", "2.0", None, "2.15.0", None)
    assert not _version_in_range("2.15.1", "2.0", None, "2.15.0", None)


def test_exclusive_end_boundary():
    assert _version_in_range("2.14.9", "2.0", None, None, "2.15.0")
    assert not _version_in_range("2.15.0", "2.0", None, None, "2.15.0")


def test_single_bound_range_low_and_high():
    assert _version_in_range("2.14.9", "2.0", None, None, "2.15.0")
    assert not _version_in_range("1.5", "2.0", None, None, "2.15.0")
    assert not _version_in_range("3.0", "2.0", None, None, "2.15.0")


def test_multi_range_matches_any_bounded_range():
    # Two disjoint affected ranges (e.g. < 1.0 and >= 2.0 < 2.15.0).
    from depwolf.application.remediation import _installed_applicability

    ranges = [("0.8", None, None, "1.0"), ("2.0", None, None, "2.15.0")]
    assert _installed_applicability("0.9", ranges) is True
    assert _installed_applicability("2.14.1", ranges) is True
    assert _installed_applicability("1.5", ranges) is False
    assert _installed_applicability("2.15.0", ranges) is False
    assert _installed_applicability("0.7", ranges) is False
    assert _installed_applicability(None, ranges) is None
    # An unbounded range means "all versions affected".
    assert _installed_applicability("9.9.9", [("0.8", None, None, "1.0"), (None, None, None, None)]) is True


def test_format_range_human_readable():
    from depwolf.domain.versions import format_range

    assert format_range("2.0", None, None, "2.15.0") == ">= 2.0 and < 2.15.0"
    assert format_range(None, "2.0", None, None) == "> 2.0"
    assert format_range(None, None, "2.15.0", None) == "<= 2.15.0"
    assert format_range(None, None, None, None) == "all versions"
