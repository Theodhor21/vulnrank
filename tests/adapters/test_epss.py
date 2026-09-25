import gzip
import json
import logging
from pathlib import Path

import httpx
import pytest
import respx

from tests.conftest import FakeClock
from vulnrank.adapters.enrichment.cache import DEFAULT_TTL, JsonCache
from vulnrank.adapters.enrichment.epss import (
    EPSS_API_URL,
    EpssApiClient,
    EpssCsvFile,
    batch_by_length,
)
from vulnrank.domain.models import EpssScore
from vulnrank.ports.enrichment import ExploitProbability
from vulnrank.ports.sources import SourceError

FIXTURES = Path(__file__).parents[1] / "fixtures" / "epss"
RESPONSE = json.loads((FIXTURES / "response.json").read_text(encoding="utf-8"))
CVES = ["CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003"]
EXPECTED = {
    "CVE-2023-0001": EpssScore(score=0.91234, percentile=0.99876),
    "CVE-2023-0002": EpssScore(score=0.00043, percentile=0.1012),
}


@pytest.fixture
def api(http_mock: respx.MockRouter) -> respx.Route:
    return http_mock.get(url__startswith=EPSS_API_URL)


@pytest.fixture
def cache(tmp_path: Path, clock: FakeClock) -> JsonCache:
    return JsonCache(tmp_path / "epss.json", clock=clock)


def _client(
    cache: JsonCache | None = None, *, offline: bool = False, sleeps: list[float] | None = None
) -> EpssApiClient:
    record = sleeps if sleeps is not None else []
    return EpssApiClient(httpx.Client(), cache=cache, offline=offline, sleep=record.append)


def _ok(data: list[object] | None = None) -> httpx.Response:
    return httpx.Response(200, json=RESPONSE if data is None else {**RESPONSE, "data": data})


# --- Fetching ----------------------------------------------------------------------------


def test_scores_are_fetched_in_one_request_with_an_explicit_limit(api: respx.Route) -> None:
    api.mock(return_value=_ok())
    source: ExploitProbability = _client()
    assert source.scores(CVES) == EXPECTED
    params = api.calls.last.request.url.params
    assert params["cve"] == ",".join(CVES)
    assert params["limit"] == "3"


def test_many_cves_are_split_into_batches_that_fit_the_parameter_limit(
    api: respx.Route,
) -> None:
    sent: list[httpx.QueryParams] = []

    def respond(request: httpx.Request) -> httpx.Response:
        sent.append(request.url.params)
        return _ok([])

    api.mock(side_effect=respond)
    cves = [f"CVE-2023-{n:05d}" for n in range(300)]
    _client().scores(cves)
    assert len(sent) == 3
    assert all(len(params["cve"]) <= 2000 for params in sent)
    assert [int(params["limit"]) for params in sent] == [133, 133, 34]
    assert sorted(cve for params in sent for cve in params["cve"].split(",")) == cves


@pytest.mark.parametrize(
    ("max_length", "expected"),
    [
        (27, [["CVE-2023-0001", "CVE-2023-0002"], ["CVE-2023-0003"]]),
        (26, [["CVE-2023-0001"], ["CVE-2023-0002"], ["CVE-2023-0003"]]),
        (2000, [CVES]),
    ],
)
def test_batch_by_length(max_length: int, expected: list[list[str]]) -> None:
    assert batch_by_length(CVES, max_length) == expected


def test_batch_by_length_of_nothing() -> None:
    assert batch_by_length([]) == []


def test_malformed_rows_are_skipped(api: respx.Route, caplog: pytest.LogCaptureFixture) -> None:
    api.mock(return_value=_ok([RESPONSE["data"][0], {"cve": "CVE-2023-0002", "epss": "high"}]))
    with caplog.at_level(logging.WARNING, logger="vulnrank"):
        scores = _client().scores(CVES)
    assert list(scores) == ["CVE-2023-0001"]
    assert "malformed EPSS row response.data[1]" in caplog.text


# --- Cache -------------------------------------------------------------------------------


def test_fresh_cache_avoids_the_network_including_for_cves_without_a_score(
    api: respx.Route, cache: JsonCache, clock: FakeClock
) -> None:
    api.mock(return_value=_ok())
    _client(cache).scores(CVES)
    clock.advance(DEFAULT_TTL / 2)
    assert _client(cache).scores(CVES) == EXPECTED
    assert api.call_count == 1


def test_expired_cache_is_refreshed(api: respx.Route, cache: JsonCache, clock: FakeClock) -> None:
    api.mock(return_value=_ok())
    _client(cache).scores(CVES)
    clock.advance(DEFAULT_TTL)
    _client(cache).scores(CVES)
    assert api.call_count == 2


def test_corrupt_cache_entry_is_looked_up_again(api: respx.Route, cache: JsonCache) -> None:
    cache.put_many({"CVE-2023-0001": {"score": "garbage"}})
    api.mock(return_value=_ok())
    assert _client(cache).scores(CVES[:1]) == {"CVE-2023-0001": EXPECTED["CVE-2023-0001"]}
    assert api.call_count == 1


def test_only_uncached_cves_are_requested(api: respx.Route, cache: JsonCache) -> None:
    api.mock(return_value=_ok())
    _client(cache).scores(CVES[:1])
    _client(cache).scores(CVES)
    assert api.calls.last.request.url.params["cve"] == "CVE-2023-0002,CVE-2023-0003"


# --- Degrading gracefully ------------------------------------------------------------------


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(httpx.Response(500), id="server-error"),
        pytest.param(httpx.ConnectError("connection refused"), id="network-error"),
        pytest.param(httpx.Response(200, text="<html>oops</html>"), id="not-json"),
        pytest.param(httpx.Response(200, json={"status": "error"}), id="unexpected-shape"),
    ],
)
def test_api_failures_leave_scores_empty_and_warn(
    api: respx.Route, caplog: pytest.LogCaptureFixture, failure: httpx.Response | Exception
) -> None:
    api.mock(side_effect=[failure])
    with caplog.at_level(logging.WARNING, logger="vulnrank"):
        assert _client().scores(CVES) == {}
    assert "EPSS lookup failed for 3 CVE(s)" in caplog.text


def test_stale_cache_is_the_fallback_when_the_api_fails(
    api: respx.Route, cache: JsonCache, clock: FakeClock, caplog: pytest.LogCaptureFixture
) -> None:
    api.mock(side_effect=[_ok(), httpx.Response(503)])
    _client(cache).scores(CVES)
    clock.advance(DEFAULT_TTL * 2)
    with caplog.at_level(logging.WARNING, logger="vulnrank"):
        assert _client(cache).scores(CVES) == EXPECTED
    assert "using stale cached EPSS scores for 2 CVE(s)" in caplog.text


def test_rate_limit_is_retried_after_the_requested_delay(api: respx.Route) -> None:
    api.mock(side_effect=[httpx.Response(429, headers={"Retry-After": "7"}), _ok()])
    sleeps: list[float] = []
    assert _client(sleeps=sleeps).scores(CVES) == EXPECTED
    assert sleeps == [7.0]


@pytest.mark.parametrize(
    ("retry_after", "expected_sleep"),
    [(None, 5.0), ("120", 60.0), ("-3", 0.0), ("Wed, 21 Oct 2026 07:28:00 GMT", 5.0)],
)
def test_retry_delay_is_bounded(
    api: respx.Route, retry_after: str | None, expected_sleep: float
) -> None:
    headers = {"Retry-After": retry_after} if retry_after else {}
    api.mock(side_effect=[httpx.Response(429, headers=headers), _ok()])
    sleeps: list[float] = []
    _client(sleeps=sleeps).scores(CVES)
    assert sleeps == [expected_sleep]


def test_persistent_rate_limiting_gives_up_after_two_retries(
    api: respx.Route, caplog: pytest.LogCaptureFixture
) -> None:
    api.mock(return_value=httpx.Response(429, headers={"Retry-After": "1"}))
    sleeps: list[float] = []
    with caplog.at_level(logging.WARNING, logger="vulnrank"):
        assert _client(sleeps=sleeps).scores(CVES) == {}
    assert api.call_count == 3
    assert sleeps == [1.0, 1.0]
    assert "429" in caplog.text


# --- Offline -----------------------------------------------------------------------------


def test_offline_uses_the_cache_whatever_its_age_and_never_calls_the_api(
    api: respx.Route, cache: JsonCache, clock: FakeClock
) -> None:
    api.mock(return_value=_ok())
    _client(cache).scores(CVES)
    clock.advance(DEFAULT_TTL * 30)
    assert _client(cache, offline=True).scores(CVES) == EXPECTED
    assert api.call_count == 1


def test_offline_without_a_cache_entry_warns(
    api: respx.Route, cache: JsonCache, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="vulnrank"):
        assert _client(cache, offline=True).scores(CVES) == {}
    assert not api.called
    assert "offline: no cached EPSS score for 3 CVE(s)" in caplog.text


# --- Local CSV export -----------------------------------------------------------------------


def test_csv_export_is_read(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="vulnrank"):
        scores = EpssCsvFile(FIXTURES / "scores.csv").scores(CVES)
    assert scores == EXPECTED
    assert "malformed EPSS row" in caplog.text


def test_gzipped_csv_export_is_read(tmp_path: Path) -> None:
    path = tmp_path / "epss_scores-2026-09-24.csv.gz"
    path.write_bytes(gzip.compress((FIXTURES / "scores.csv").read_bytes()))
    assert EpssCsvFile(path).scores(CVES) == EXPECTED


def test_csv_file_is_read_once(tmp_path: Path) -> None:
    path = tmp_path / "scores.csv"
    path.write_bytes((FIXTURES / "scores.csv").read_bytes())
    source = EpssCsvFile(path)
    source.scores(CVES)
    path.unlink()
    assert source.scores(CVES) == EXPECTED


@pytest.mark.parametrize(
    ("name", "content"),
    [("missing.csv", None), ("broken.csv.gz", b"not gzip at all")],
)
def test_unreadable_csv_is_a_source_error(tmp_path: Path, name: str, content: bytes | None) -> None:
    path = tmp_path / name
    if content is not None:
        path.write_bytes(content)
    with pytest.raises(SourceError, match="cannot read EPSS file"):
        EpssCsvFile(path).scores(CVES)
