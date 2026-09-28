import json
import logging
from datetime import date, timedelta
from pathlib import Path

import httpx
import pytest
import respx

from tests.conftest import FakeClock
from vulnrank.adapters.enrichment.cache import DEFAULT_TTL, JsonCache
from vulnrank.adapters.enrichment.kev import (
    CACHE_KEY,
    KEV_FEED_URL,
    KevFeedClient,
    KevJsonFile,
    parse_feed,
)
from vulnrank.domain.models import KevEntry
from vulnrank.ports.enrichment import KnownExploitedCatalog
from vulnrank.ports.sources import SourceError

FEED_PATH = Path(__file__).parents[1] / "fixtures" / "kev" / "feed.json"
FEED = json.loads(FEED_PATH.read_text(encoding="utf-8"))
CVES = ["CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0005"]
EXPECTED = {
    "CVE-2023-0001": KevEntry(cve_id="CVE-2023-0001", date_added=date(2024, 1, 10)),
    "CVE-2023-0005": KevEntry(cve_id="CVE-2023-0005", date_added=date(2025, 6, 2)),
}
CATALOG = {
    **EXPECTED,
    # A bad dateAdded must not cost a CVE its KEV status.
    "CVE-2023-0006": KevEntry(cve_id="CVE-2023-0006", date_added=None),
}


@pytest.fixture
def feed(http_mock: respx.MockRouter) -> respx.Route:
    return http_mock.get(KEV_FEED_URL)


@pytest.fixture
def cache(tmp_path: Path, clock: FakeClock) -> JsonCache:
    return JsonCache(tmp_path / "kev.json", clock=clock)


def _client(cache: JsonCache | None = None, *, offline: bool = False) -> KevFeedClient:
    return KevFeedClient(httpx.Client(), cache=cache, offline=offline, sleep=lambda _: None)


# --- Parsing -------------------------------------------------------------------------------


def test_feed_is_parsed_and_a_bad_date_keeps_the_entry(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="vulnrank"):
        catalog = parse_feed(FEED)
    assert catalog == CATALOG
    assert "KEV entry vulnerabilities[2] (CVE-2023-0006) has an invalid dateAdded" in caplog.text


def test_a_document_that_is_not_a_feed_is_rejected() -> None:
    with pytest.raises(ValueError, match="not a CISA KEV feed"):
        parse_feed({"catalogVersion": "x"})


# --- Fetching and caching --------------------------------------------------------------------


def test_catalog_is_downloaded_once_per_client(feed: respx.Route) -> None:
    feed.mock(return_value=httpx.Response(200, json=FEED))
    source: KnownExploitedCatalog = _client()
    assert source.lookup(CVES) == EXPECTED
    assert source.lookup(["CVE-2023-0005"]) == {"CVE-2023-0005": EXPECTED["CVE-2023-0005"]}
    assert feed.call_count == 1


def test_fresh_cache_avoids_the_download(
    feed: respx.Route, cache: JsonCache, clock: FakeClock
) -> None:
    feed.mock(return_value=httpx.Response(200, json=FEED))
    _client(cache).lookup(CVES)
    clock.advance(DEFAULT_TTL / 2)
    assert _client(cache).lookup(CVES) == EXPECTED
    assert feed.call_count == 1


def test_expired_cache_is_refreshed(feed: respx.Route, cache: JsonCache, clock: FakeClock) -> None:
    feed.mock(return_value=httpx.Response(200, json=FEED))
    _client(cache).lookup(CVES)
    clock.advance(DEFAULT_TTL)
    _client(cache).lookup(CVES)
    assert feed.call_count == 2


def test_corrupt_cache_entry_is_ignored(feed: respx.Route, cache: JsonCache) -> None:
    cache.put_many({CACHE_KEY: {"CVE-2023-0001": "not-a-date"}})
    feed.mock(return_value=httpx.Response(200, json=FEED))
    assert _client(cache).lookup(CVES) == EXPECTED
    assert feed.call_count == 1


# --- Degrading gracefully --------------------------------------------------------------------


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(httpx.Response(500), id="server-error"),
        pytest.param(httpx.ReadTimeout("timed out"), id="timeout"),
        pytest.param(httpx.Response(200, json={"unexpected": True}), id="not-a-feed"),
    ],
)
def test_download_failure_without_cache_marks_nothing_and_warns(
    feed: respx.Route, caplog: pytest.LogCaptureFixture, failure: httpx.Response | Exception
) -> None:
    feed.mock(side_effect=[failure])
    client = _client()
    with caplog.at_level(logging.WARNING, logger="vulnrank"):
        assert client.lookup(CVES) == {}
    assert "KEV download failed" in caplog.text
    assert "no CVE is marked as in KEV" in caplog.text
    assert len(client.issues()) == 1
    assert client.issues()[0].startswith("KEV download failed")


def test_download_failure_falls_back_to_a_stale_cache(
    feed: respx.Route, cache: JsonCache, clock: FakeClock, caplog: pytest.LogCaptureFixture
) -> None:
    feed.mock(side_effect=[httpx.Response(200, json=FEED), httpx.Response(502)])
    _client(cache).lookup(CVES)
    clock.advance(DEFAULT_TTL * 3)
    with caplog.at_level(logging.WARNING, logger="vulnrank"):
        assert _client(cache).lookup(CVES) == EXPECTED
    assert "using the stale cached catalog" in caplog.text


def test_a_downloaded_or_stale_catalog_is_not_an_issue(
    feed: respx.Route, cache: JsonCache, clock: FakeClock
) -> None:
    feed.mock(side_effect=[httpx.Response(200, json=FEED), httpx.Response(502)])
    fresh = _client(cache)
    fresh.lookup(CVES)
    clock.advance(DEFAULT_TTL * 3)
    stale = _client(cache)
    stale.lookup(CVES)
    assert fresh.issues() == stale.issues() == ()


# --- Offline ---------------------------------------------------------------------------------


def test_offline_uses_a_stale_cache_without_downloading(
    feed: respx.Route, cache: JsonCache, clock: FakeClock
) -> None:
    feed.mock(return_value=httpx.Response(200, json=FEED))
    _client(cache).lookup(CVES)
    clock.advance(DEFAULT_TTL * 30)
    assert _client(cache, offline=True).lookup(CVES) == EXPECTED
    assert feed.call_count == 1


def test_offline_without_cache_warns(
    feed: respx.Route, cache: JsonCache, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="vulnrank"):
        assert _client(cache, offline=True).lookup(CVES) == {}
    assert not feed.called
    assert "offline: no cached KEV catalog" in caplog.text


def test_offline_without_cache_is_an_issue(cache: JsonCache) -> None:
    client = _client(cache, offline=True)
    client.lookup(CVES)
    assert client.issues() == ("offline: no cached KEV catalog",)


def test_local_feed_file_has_no_issues() -> None:
    source = KevJsonFile(FEED_PATH)
    source.lookup(CVES)
    assert source.issues() == ()


# --- Local file ------------------------------------------------------------------------------


def test_local_feed_file_is_read_once(tmp_path: Path) -> None:
    path = tmp_path / "kev.json"
    path.write_bytes(FEED_PATH.read_bytes())
    source = KevJsonFile(path)
    assert source.lookup(CVES) == EXPECTED
    path.unlink()
    assert source.lookup(CVES) == EXPECTED


def test_local_file_that_is_not_a_feed_is_a_source_error(tmp_path: Path) -> None:
    path = tmp_path / "kev.json"
    path.write_text('{"hello": "world"}', encoding="utf-8")
    with pytest.raises(SourceError, match="not a CISA KEV feed"):
        KevJsonFile(path).lookup(CVES)


def test_missing_local_file_is_a_source_error(tmp_path: Path) -> None:
    with pytest.raises(SourceError, match="cannot read"):
        KevJsonFile(tmp_path / "nope.json").lookup(CVES)


def test_an_entry_without_a_cve_id_is_skipped(caplog: pytest.LogCaptureFixture) -> None:
    feed = {"vulnerabilities": [{"dateAdded": "2024-01-01"}, {"cveID": "CVE-2024-0001"}]}
    with caplog.at_level(logging.WARNING, logger="vulnrank"):
        catalog = parse_feed(feed)
    assert list(catalog) == ["CVE-2024-0001"]
    assert "vulnerabilities[0]" in caplog.text


def test_an_offline_catalog_older_than_a_week_is_an_issue(
    feed: respx.Route, cache: JsonCache, clock: FakeClock
) -> None:
    feed.mock(return_value=httpx.Response(200, json=FEED))
    _client(cache).lookup(CVES)
    clock.advance(timedelta(days=8))
    client = _client(cache, offline=True)
    assert client.lookup(CVES) == EXPECTED
    assert client.issues() == ("the KEV catalog is 8 days old",)
