import logging
from datetime import timedelta
from pathlib import Path

import pytest

from tests.conftest import FakeClock
from vulnrank.adapters.enrichment.cache import JsonCache, default_cache_dir, utc_now


def test_values_survive_a_new_instance(tmp_path: Path, clock: FakeClock) -> None:
    JsonCache(tmp_path / "c.json", clock=clock).put_many({"a": {"x": 1}, "b": None})
    reopened = JsonCache(tmp_path / "c.json", clock=clock)
    a, b = reopened.get("a"), reopened.get("b")
    assert a is not None
    assert b is not None
    assert (a.value, a.fetched_at) == ({"x": 1}, clock.now)
    assert b.value is None
    assert reopened.get("missing") is None


def test_entries_expire_after_the_ttl(tmp_path: Path, clock: FakeClock) -> None:
    cache = JsonCache(tmp_path / "c.json", ttl=timedelta(hours=1), clock=clock)
    cache.put_many({"a": 1})
    entry = cache.get("a")
    assert entry is not None
    clock.advance(timedelta(minutes=59))
    assert cache.is_fresh(entry)
    clock.advance(timedelta(minutes=1))
    assert not cache.is_fresh(entry)


def test_default_clock_is_timezone_aware_utc() -> None:
    assert utc_now().utcoffset() == timedelta(0)


def test_parent_directories_are_created(tmp_path: Path, clock: FakeClock) -> None:
    path = tmp_path / "deep" / "er" / "c.json"
    JsonCache(path, clock=clock).put_many({"a": 1})
    assert path.exists()


def test_nothing_is_written_for_an_empty_update(tmp_path: Path, clock: FakeClock) -> None:
    JsonCache(tmp_path / "c.json", clock=clock).put_many({})
    assert not (tmp_path / "c.json").exists()


def test_corrupt_file_is_ignored_with_a_warning(
    tmp_path: Path, clock: FakeClock, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "c.json"
    path.write_text("{definitely not json", encoding="utf-8")
    cache = JsonCache(path, clock=clock)
    with caplog.at_level(logging.WARNING, logger="vulnrank"):
        assert cache.get("a") is None
    assert "ignoring unreadable cache file" in caplog.text
    cache.put_many({"a": 1})
    assert JsonCache(path, clock=clock).get("a") is not None


def test_write_failure_is_logged_not_raised(
    tmp_path: Path, clock: FakeClock, caplog: pytest.LogCaptureFixture
) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("", encoding="utf-8")
    cache = JsonCache(blocker / "c.json", clock=clock)
    with caplog.at_level(logging.WARNING, logger="vulnrank"):
        cache.put_many({"a": 1})
    assert "could not write cache file" in caplog.text
    assert cache.get("a") is not None  # still usable for this run


@pytest.mark.parametrize(
    ("environ", "expected"),
    [
        ({"XDG_CACHE_HOME": "/tmp/xdg"}, Path("/tmp/xdg/vulnrank")),
        ({}, Path.home() / ".cache" / "vulnrank"),
        ({"XDG_CACHE_HOME": ""}, Path.home() / ".cache" / "vulnrank"),
    ],
)
def test_default_cache_dir(environ: dict[str, str], expected: Path) -> None:
    assert default_cache_dir(environ) == expected
