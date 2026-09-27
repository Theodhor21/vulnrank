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
from vulnrank.adapters.inputs.baseline import load_baseline
from vulnrank.adapters.inputs.detect import InputFormat, open_source
from vulnrank.adapters.outputs.json_report import JsonReporter
from vulnrank.adapters.outputs.markdown import MarkdownReporter
from vulnrank.adapters.outputs.sarif import SarifReporter
from vulnrank.adapters.outputs.table import TableReporter
from vulnrank.adapters.suppressions.openvex import load_openvex
from vulnrank.adapters.suppressions.trivyignore import load_trivyignore
from vulnrank.application.service import AssetLookup, prioritise
from vulnrank.config import Config, ConfigError, load_config
from vulnrank.domain.models import Asset, Priority, Report
from vulnrank.ports.enrichment import ExploitProbability, KnownExploitedCatalog
from vulnrank.ports.reporting import Reporter
from vulnrank.ports.sources import SourceError

logger = logging.getLogger(__name__)

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


class View(StrEnum):
    FINDINGS = "findings"
    FIXES = "fixes"


ReporterFactory = Callable[[bool, str | None], Reporter]  # (fix plan view?, SARIF uri)

REPORTERS: dict[OutputFormat, ReporterFactory] = {
    OutputFormat.TABLE: lambda fixes, _: TableReporter(fixes=fixes),
    OutputFormat.JSON: lambda _fixes, _uri: JsonReporter(),  # always includes the fix plan
    OutputFormat.MARKDOWN: lambda fixes, _: MarkdownReporter(fixes=fixes),
    OutputFormat.SARIF: lambda _, sarif_uri: SarifReporter(artifact_uri=sarif_uri),
}


app = typer.Typer(add_completion=False, pretty_exceptions_enable=False)


def _print_version(value: bool) -> None:
    if value:
        typer.echo(f"vulnrank {__version__}")
        raise typer.Exit


@app.command()
def main(
    scan: Annotated[
        Path,
        typer.Argument(
            help="Trivy or Grype JSON report, or CycloneDX JSON SBOM.", show_default=False
        ),
    ],
    assets: Annotated[
        Path | None, typer.Option("--assets", "-a", help="TOML file with asset context.")
    ] = None,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="Output format.")
    ] = OutputFormat.TABLE,
    top: Annotated[
        int, typer.Option(min=0, help="List at most N findings or upgrades (0 = all).")
    ] = 20,
    view: Annotated[
        View,
        typer.Option(help="List findings, or upgrades grouped by fix (table and Markdown)."),
    ] = View.FINDINGS,
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
    target: Annotated[
        str | None,
        typer.Option(help="Report findings under this name (and match assets against it)."),
    ] = None,
    vex: Annotated[
        list[Path] | None,
        typer.Option("--vex", help="OpenVEX document; not_affected/fixed statements suppress."),
    ] = None,
    ignore_file: Annotated[
        list[Path] | None,
        typer.Option(help="A .trivyignore file; listed IDs are suppressed, with expiry."),
    ] = None,
    baseline: Annotated[
        Path | None,
        typer.Option(help="Earlier vulnrank JSON report; --fail-on then counts only changes."),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option("--strict", help="Exit with code 2 if EPSS or KEV data could not be loaded."),
    ] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show info logs.")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Only show errors.")] = False,
    _version: Annotated[
        bool | None,
        typer.Option("--version", callback=_print_version, is_eager=True, help="Show version."),
    ] = None,
) -> None:
    """Rank the findings of a vulnerability scan, with a reason for every decision."""
    if verbose and quiet:
        raise typer.BadParameter("--verbose and --quiet cannot be used together")
    if view is View.FIXES and output_format is OutputFormat.SARIF:
        raise typer.BadParameter("--view fixes is not available for SARIF output")
    _configure_logging(verbose=verbose, quiet=quiet)
    cache = None if no_cache else cache_dir or default_cache_dir()
    try:
        config = load_config(assets) if assets else Config()
        source = open_source(scan, input_format)
        rules = config.ignore + tuple(r for f in ignore_file or () for r in load_trivyignore(f))
        statements = tuple(s for f in vex or () for s in load_openvex(f))
        previous = load_baseline(baseline) if baseline else None
        with _http_client() as http:
            report = prioritise(
                source,
                _epss(http, epss_file, cache, offline=offline),
                _kev(http, kev_file, cache, offline=offline),
                asset_for=_asset_lookup(config),
                policy=config.scoring,
                target=target,
                rules=rules,
                statements=statements,
                baseline=previous,
            )
        reporter = REPORTERS[output_format](view is View.FIXES, sarif_uri)
        _write(report, reporter, limit=top or None, output=output)
    except (ConfigError, SourceError, OSError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_ERROR) from exc
    except Exception as exc:
        # Exit code 1 means "findings at or above --fail-on"; a crash must never look like that.
        logger.info("unexpected error", exc_info=True)
        typer.echo(f"internal error: {exc} (run with --verbose for details)", err=True)
        raise typer.Exit(EXIT_ERROR) from exc
    if strict and report.enrichment_issues:
        typer.echo(f"error: enrichment incomplete: {'; '.join(report.enrichment_issues)}", err=True)
        raise typer.Exit(EXIT_ERROR)
    if fail_on is not None and report.has_findings_at_or_above(fail_on):
        raise typer.Exit(EXIT_FINDINGS)


def _asset_lookup(config: Config) -> AssetLookup:
    """Resolve assets, warning once per scan target that no [[assets]] entry matches."""
    warned: set[str] = set()

    def lookup(target: str) -> Asset:
        asset = config.match_asset(target)
        if asset is not None:
            return asset
        if config.assets and target not in warned:
            warned.add(target)
            logger.warning(
                "no [[assets]] entry matches %r; using default_asset (criticality %s)",
                target,
                config.default_asset.criticality,
            )
        return config.asset_for(target)

    return lookup


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
    package_logger = logging.getLogger("vulnrank")
    package_logger.handlers[:] = [handler]
    package_logger.setLevel(level)
