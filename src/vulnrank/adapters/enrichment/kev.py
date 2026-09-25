"""CISA Known Exploited Vulnerabilities, from the official JSON feed or a downloaded copy.

Feed facts this relies on (checked against the CISA schema, 2026-09): the document has a
`vulnerabilities` array whose items carry `cveID` and `dateAdded` (YYYY-MM-DD).
"""

import logging
import time
from collections.abc import Collection, Mapping
from datetime import date
from pathlib import Path

import httpx
from pydantic import Field, TypeAdapter, ValidationError

from vulnrank.adapters._raw import RawModel, describe, read_json
from vulnrank.adapters.enrichment._http import Sleep, get_json
from vulnrank.adapters.enrichment.cache import JsonCache
from vulnrank.domain.models import KevEntry
from vulnrank.ports.sources import SourceError

logger = logging.getLogger(__name__)

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_KEY = "catalog"

Catalog = dict[str, KevEntry]
_CACHED_CATALOG = TypeAdapter(dict[str, date])


class _Feed(RawModel):
    vulnerabilities: list[object]


class _Item(RawModel):
    cve_id: str = Field(alias="cveID")
    date_added: date = Field(alias="dateAdded")


def parse_feed(document: object) -> Catalog:
    """Raise ValueError if the document is not a KEV feed; skip malformed entries."""
    try:
        feed = _Feed.model_validate(document)
    except ValidationError as exc:
        raise ValueError(f"not a CISA KEV feed ({describe(exc)})") from exc
    catalog: Catalog = {}
    for index, raw in enumerate(feed.vulnerabilities):
        try:
            item = _Item.model_validate(raw)
            entry = KevEntry(cve_id=item.cve_id, date_added=item.date_added)
        except ValidationError as exc:
            logger.warning(
                "skipping malformed KEV entry vulnerabilities[%d]: %s", index, describe(exc)
            )
            continue
        catalog[entry.cve_id] = entry
    return catalog


def _lookup(catalog: Catalog, cve_ids: Collection[str]) -> dict[str, KevEntry]:
    return {cve: catalog[cve] for cve in cve_ids if cve in catalog}


class KevFeedClient:
    """Implements KnownExploitedCatalog against the CISA feed, with an optional cache.

    The catalog is small (~1.5k entries), so it is fetched whole and cached as one entry.
    Offline, only the cache is used. If a fetch fails, a stale cache is the fallback;
    without one, every CVE is reported as not in KEV and a warning explains why.
    """

    def __init__(
        self,
        http: httpx.Client,
        *,
        cache: JsonCache | None = None,
        offline: bool = False,
        url: str = KEV_FEED_URL,
        sleep: Sleep = time.sleep,
    ) -> None:
        self._http = http
        self._cache = cache
        self._offline = offline
        self._url = url
        self._sleep = sleep
        self._catalog: Catalog | None = None

    def lookup(self, cve_ids: Collection[str]) -> Mapping[str, KevEntry]:
        if self._catalog is None:
            self._catalog = self._load()
        return _lookup(self._catalog, cve_ids)

    def _load(self) -> Catalog:
        cached: Catalog | None = None
        fresh = False
        if self._cache is not None and (entry := self._cache.get(CACHE_KEY)) is not None:
            cached = _decode(entry.value)
            fresh = self._cache.is_fresh(entry)
        if cached is not None and (self._offline or fresh):
            return cached
        if self._offline:
            logger.warning("offline: no cached KEV catalog, so no CVE is marked as in KEV")
            return {}
        try:
            catalog = parse_feed(get_json(self._http, self._url, sleep=self._sleep))
        except (httpx.HTTPError, ValueError) as exc:
            return self._fallback(cached, exc)
        if self._cache:
            self._cache.put_many({CACHE_KEY: _encode(catalog)})
        return catalog

    def _fallback(self, stale: Catalog | None, exc: Exception) -> Catalog:
        if stale is not None:
            logger.warning("KEV download failed (%s); using the stale cached catalog", exc)
            return stale
        logger.warning("KEV download failed (%s); no CVE is marked as in KEV", exc)
        return {}


def _encode(catalog: Catalog) -> dict[str, str]:
    return {cve: entry.date_added.isoformat() for cve, entry in catalog.items()}


def _decode(value: object) -> Catalog | None:
    try:
        dates = _CACHED_CATALOG.validate_python(value)
        return {cve: KevEntry(cve_id=cve, date_added=added) for cve, added in dates.items()}
    except ValidationError:
        return None


class KevJsonFile:
    """Implements KnownExploitedCatalog from a downloaded copy of the feed."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._catalog: Catalog | None = None

    def lookup(self, cve_ids: Collection[str]) -> Mapping[str, KevEntry]:
        if self._catalog is None:
            try:
                self._catalog = parse_feed(read_json(self._path))
            except ValueError as exc:
                raise SourceError(f"{self._path}: {exc}") from exc
        return _lookup(self._catalog, cve_ids)
