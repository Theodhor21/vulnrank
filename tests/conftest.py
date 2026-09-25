from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
import respx


@pytest.fixture(autouse=True)
def http_mock() -> Iterator[respx.MockRouter]:
    """Every test runs inside respx: an HTTP request without a matching route fails the test."""
    with respx.mock(assert_all_called=False) as router:
        yield router


class FakeClock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, delta: timedelta) -> None:
        self.now += delta


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(datetime(2026, 9, 25, 12, 0, tzinfo=UTC))
