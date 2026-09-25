"""GET-JSON with a polite retry on HTTP 429."""

import time
from collections.abc import Callable, Mapping
from http import HTTPStatus

import httpx

Sleep = Callable[[float], None]

MAX_RETRY_AFTER_SECONDS = 60.0
DEFAULT_RETRY_AFTER_SECONDS = 5.0


def get_json(
    http: httpx.Client,
    url: str,
    *,
    params: Mapping[str, str | int] | None = None,
    max_retries: int = 2,
    sleep: Sleep = time.sleep,
) -> object:
    """Raise httpx.HTTPError on transport or status errors, ValueError on a non-JSON body."""
    retries = 0
    while True:
        response = http.get(url, params=params)
        if response.status_code == HTTPStatus.TOO_MANY_REQUESTS and retries < max_retries:
            retries += 1
            sleep(_retry_after(response))
            continue
        response.raise_for_status()
        return response.json()


def _retry_after(response: httpx.Response) -> float:
    try:
        seconds = float(response.headers.get("Retry-After", DEFAULT_RETRY_AFTER_SECONDS))
    except ValueError:
        seconds = DEFAULT_RETRY_AFTER_SECONDS
    return min(max(seconds, 0.0), MAX_RETRY_AFTER_SECONDS)
