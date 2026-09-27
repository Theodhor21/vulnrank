"""Command-line entry point: the only module that knows the concrete adapters."""

import logging
import sys
from collections.abc import Callable
from contextlib import ExitStack
from enum import StrEnum
from pathlib import Path
from typing import Annotated, TextIO

import httpx
import typer
from rich.console import Console
from rich.logging import RichHandler

from vulnrank import __version__
from vulnrank.adapters.enrichment.cache import JsonCache, default_cache_dir
from vulnrank.adapters.enrichment.epss import EpssApiClient, EpssCsvFile
from vulnrank.adapters.enrichment.kev import KevFeedClient, KevJsonFile
from vulnrank.adapters.inputs.detect import InputFormat, open_source
from vulnrank.adapters.outputs.json_report import JsonReporter
from vulnrank.adapters.outputs.markdown import MarkdownReporter
from vulnrank.adapters.outputs.sarif import SarifReporter
from vulnrank.adapters.outputs.table import TableReporter
from vulnrank.application.service import prioritise
from vulnrank.config import Config, ConfigError, load_config
from vulnrank.domain.models import Priority, Report
from vulnrank.ports.enrichment import ExploitProbability, KnownExploitedCatalog
from vulnrank.ports.reporting import Reporter
from vulnrank.ports.sources import SourceError

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

USER_AGENT = f"vulnrank/{__version__} (+https://github.com/Theodhor21/vulnrank)"
HTTP_TIMEOUT_SECONDS = 30.0


class OutputFormat(StrEnum):
    TABLE = "table"
    JSON = "json"
    MARKDOWN = "markdown"
    SARIF = "sarif"


REPORTERS: dict[OutputFormat, Callable[[str | None], Reporter]] = {
    OutputFormat.TABLE: lambda _: TableReporter(),
    OutputFormat.JSON: lambda _: JsonReporter(),
    OutputFormat.MARKDOWN: lambda _: MarkdownReporter(),
    OutputFormat.SARIF: lambda sarif_uri: SarifReporter(artifact_uri=sarif_uri),
}


app = typer.Typer(add_completion=False, pretty_exceptions_enable=False)


def _print_version(value: bool) -> None:
    if value:
        typer.echo(f"vulnrank {__version__}")
        raise typer.Exit


@app.command()
def main(
    scan: Annotated[
        Path, typer.Argument(help="Trivy JSON report or CycloneDX JSON SBOM.", show_default=False)
    ],
    assets: Annotated[
        Path | None, typer.Option("--assets", "-a", help="TOML file with asset context.")
    ] = None,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="Output format.")
    ] = OutputFormat.TABLE,
    top: Annotated[int, typer.Option(min=0, help="List at most N findings (0 = all).")] = 20,
    fail_on: Annotated[
        Priority | None,
        typer.Option(
            case_sensitive=False, help="Exit with code 1 if any finding is at this tier or above."
        ),
    ] = None,
    input_format: Annotated[InputFormat, typer.Option(help="Scan format.")] = InputFormat.AUTO,
    offline: Annotated[
        bool, typer.Option("--offline", help="No network: use only the cache and local files.")
    ] = False,
    epss_file: Annotated[
        Path | None, typer.Option(help="Local EPSS export (.csv or .csv.gz) instead of the API.")
    ] = None,
    kev_file: Annotated[
        Path | None, typer.Option(help="Local copy of the CISA KEV JSON feed.")
    ] = None,
    cache_dir: Annotated[
        Path | None, typer.Option(help="Cache directory [default: ~/.cache/vulnrank].")
    ] = None,
    no_cache: Annotated[
        bool, typer.Option("--no-cache", help="Neither read nor write the cache.")
    ] = False,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the report to this file.")
    ] = None,
    sarif_uri: Annotated[
        str | None,
        typer.Option(help="Repository file SARIF alerts point to, e.g. your Dockerfile."),
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show info logs.")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Only show errors.")] = False,
    _version: Annotated[
        bool | None,
        typer.Option("--version", callback=_print_version, is_eager=True, help="Show version."),
    ] = None,
) -> None:
    """Rank the findings of a vulnerability scan, with a reason for every decision."""
    _configure_logging(verbose=verbose, quiet=quiet)
    cache = None if no_cache else cache_dir or default_cache_dir()
    try:
        config = load_config(assets) if assets else Config()
        source = open_source(scan, input_format)
        with _http_client() as http:
            report = prioritise(
                source,
                _epss(http, epss_file, cache, offline=offline),
                _kev(http, kev_file, cache, offline=offline),
                asset_for=config.asset_for,
                policy=config.scoring,
            )
        reporter = REPORTERS[output_format](sarif_uri)
        _write(report, reporter, limit=top or None, output=output)
    except (ConfigError, SourceError, OSError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR) from exc
    if fail_on is not None and report.has_findings_at_or_above(fail_on):
        raise typer.Exit(EXIT_FINDINGS)


def _http_client() -> httpx.Client:
    return httpx.Client(
        timeout=HTTP_TIMEOUT_SECONDS, headers={"User-Agent": USER_AGENT}, follow_redirects=True
    )


def _epss(
    http: httpx.Client, path: Path | None, cache: Path | None, *, offline: bool
) -> ExploitProbability:
    if path is not None:
        return EpssCsvFile(path)
    return EpssApiClient(http, cache=_cache(cache, "epss.json"), offline=offline)


def _kev(
    http: httpx.Client, path: Path | None, cache: Path | None, *, offline: bool
) -> KnownExploitedCatalog:
    if path is not None:
        return KevJsonFile(path)
    return KevFeedClient(http, cache=_cache(cache, "kev.json"), offline=offline)


def _cache(directory: Path | None, name: str) -> JsonCache | None:
    return None if directory is None else JsonCache(directory / name)


def _write(report: Report, reporter: Reporter, *, limit: int | None, output: Path | None) -> None:
    with ExitStack() as stack:
        out: TextIO = sys.stdout
        if output is not None:
            out = stack.enter_context(output.open("w", encoding="utf-8"))
        reporter.write(report, out, limit=limit)


def _configure_logging(*, verbose: bool, quiet: bool) -> None:
    """Logs go to stderr so that stdout carries only the report."""
    level = logging.ERROR if quiet else logging.INFO if verbose else logging.WARNING
    handler = RichHandler(
        console=Console(stderr=True), show_time=False, show_path=False, markup=False
    )
    logger = logging.getLogger("vulnrank")
    logger.handlers[:] = [handler]
    logger.setLevel(level)
