"""End-to-end: run the real CLI against fixture files. No network (see conftest)."""

import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from typer.testing import CliRunner, Result

from vulnrank import __version__
from vulnrank.adapters.enrichment.epss import EPSS_API_URL
from vulnrank.adapters.enrichment.kev import KEV_FEED_URL
from vulnrank.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, app

FIXTURES = Path(__file__).parent / "fixtures"
TRIVY = FIXTURES / "trivy" / "basic.json"
CYCLONEDX = FIXTURES / "cyclonedx" / "basic.json"
LOCAL_INTEL = [
    "--offline",
    "--epss-file",
    str(FIXTURES / "epss" / "scores.csv"),
    "--kev-file",
    str(FIXTURES / "kev" / "feed.json"),
]
ASSETS = ["--assets", str(FIXTURES / "e2e-assets.toml")]


@pytest.fixture(autouse=True)
def _reset_logging() -> Iterator[None]:
    yield
    logger = logging.getLogger("vulnrank")
    logger.handlers.clear()
    logger.setLevel(logging.NOTSET)


def _run(*args: str) -> Result:
    return CliRunner().invoke(app, list(args), env={"COLUMNS": "200"})


def _json(*args: str) -> dict[str, Any]:
    result = _run(*args, "--format", "json")
    assert result.exit_code == EXIT_OK, result.output
    return json.loads(result.stdout)


def _ranked(document: dict[str, Any]) -> list[tuple[str, str, str]]:
    return [(f["priority"], f["cve"], f["component"]["name"]) for f in document["findings"]]


# --- Happy path ------------------------------------------------------------------------------


def test_scan_is_ranked_with_asset_context() -> None:
    assert _ranked(_json(str(TRIVY), *ASSETS, *LOCAL_INTEL)) == [
        ("P1", "CVE-2023-0001", "openssl"),  # in KEV
        ("P2", "CVE-2023-0002", "libssl3"),  # CVSS 9.8 on a critical asset
        ("P2", "CVE-2023-0002", "openssl"),
        ("P4", "CVE-2023-0003", "requests"),
    ]


def test_without_asset_config_the_default_criticality_applies() -> None:
    ranked = _ranked(_json(str(TRIVY), *LOCAL_INTEL))
    assert [priority for priority, _, _ in ranked] == ["P1", "P3", "P3", "P4"]


def test_both_input_formats_give_the_same_result() -> None:
    from_trivy = _json(str(TRIVY), *ASSETS, *LOCAL_INTEL)
    from_cyclonedx = _json(str(CYCLONEDX), *ASSETS, *LOCAL_INTEL)
    assert from_trivy["findings"] == from_cyclonedx["findings"]


def test_table_is_the_default_format() -> None:
    result = _run(str(TRIVY), *ASSETS, *LOCAL_INTEL)
    assert result.exit_code == EXIT_OK
    assert "vulnrank: demo-app:1.0" in result.stdout
    assert "in CISA KEV (added 2024-01-10)" in result.stdout
    assert "P1: 1 · P2: 2 · P3: 0 · P4: 1" in result.stdout


def test_markdown_format() -> None:
    result = _run(str(TRIVY), *LOCAL_INTEL, "--format", "markdown")
    assert result.stdout.startswith("## vulnrank: demo-app:1.0")


@pytest.mark.parametrize(("top", "listed"), [("1", 1), ("0", 4), ("99", 4)])
def test_top_limits_the_listed_findings(top: str, listed: int) -> None:
    document = _json(str(TRIVY), *LOCAL_INTEL, "--top", top)
    assert len(document["findings"]) == listed


def test_report_can_be_written_to_a_file(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    result = _run(str(TRIVY), *LOCAL_INTEL, "--format", "json", "--output", str(out))
    assert result.exit_code == EXIT_OK
    assert result.stdout == ""
    assert json.loads(out.read_text(encoding="utf-8"))["summary"]["unique_findings"] == 4


# --- CI gate ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("threshold", "expected"),
    [("P1", EXIT_FINDINGS), ("p2", EXIT_FINDINGS), ("P4", EXIT_FINDINGS)],
)
def test_fail_on_exits_1_when_a_finding_meets_the_threshold(threshold: str, expected: int) -> None:
    assert _run(str(TRIVY), *LOCAL_INTEL, "--fail-on", threshold).exit_code == expected


def test_fail_on_passes_when_nothing_meets_the_threshold() -> None:
    # malformed.json yields a single finding with no CVSS, EPSS or KEV data: P4.
    scan = str(FIXTURES / "trivy" / "malformed.json")
    assert _run(scan, *LOCAL_INTEL, "--fail-on", "P3", "-q").exit_code == EXIT_OK


def test_fail_on_considers_findings_beyond_top() -> None:
    result = _run(str(TRIVY), *LOCAL_INTEL, "--top", "1", "--fail-on", "P4")
    assert result.exit_code == EXIT_FINDINGS


# --- Errors ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["missing.json"], "cannot read missing.json"),
        ([str(FIXTURES / "assets.toml")], "not valid JSON"),
        ([str(FIXTURES / "kev" / "feed.json")], "cannot tell the format"),
        ([str(TRIVY), "--assets", str(FIXTURES / "missing.toml")], "cannot read config file"),
        ([str(TRIVY), "--offline", "--epss-file", "nope.csv"], "cannot read EPSS file"),
    ],
    ids=["missing-scan", "not-json", "unknown-format", "missing-config", "missing-epss-file"],
)
def test_input_errors_exit_2_with_a_message(args: list[str], message: str) -> None:
    result = _run(*args, "--offline", "--no-cache")
    assert result.exit_code == EXIT_ERROR
    assert message in result.stderr


def test_unwritable_output_exits_2(tmp_path: Path) -> None:
    result = _run(str(TRIVY), *LOCAL_INTEL, "--output", str(tmp_path / "no" / "dir.json"))
    assert result.exit_code == EXIT_ERROR
    assert "error:" in result.stderr


@pytest.mark.parametrize("args", [["--format", "xml"], ["--fail-on", "P9"], ["--top", "-1"], []])
def test_usage_errors_exit_2(args: list[str]) -> None:
    scan = [str(TRIVY)] if args else []
    assert _run(*scan, *args).exit_code == EXIT_ERROR


# --- Online path, cache and offline -----------------------------------------------------------


def test_online_run_fills_the_cache_and_a_later_offline_run_uses_it(
    tmp_path: Path, http_mock: respx.MockRouter
) -> None:
    epss = http_mock.get(url__startswith=EPSS_API_URL).mock(
        return_value=httpx.Response(
            200, json=json.loads((FIXTURES / "epss" / "response.json").read_text("utf-8"))
        )
    )
    kev = http_mock.get(KEV_FEED_URL).mock(
        return_value=httpx.Response(
            200, json=json.loads((FIXTURES / "kev" / "feed.json").read_text("utf-8"))
        )
    )
    cache = ["--cache-dir", str(tmp_path)]
    online = _json(str(TRIVY), *ASSETS, *cache, "-q")
    offline = _json(str(TRIVY), *ASSETS, *cache, "--offline")
    assert online == offline
    assert (epss.call_count, kev.call_count) == (1, 1)
    assert epss.calls.last.request.headers["User-Agent"].startswith("vulnrank/")


def test_offline_without_cache_still_produces_a_report(tmp_path: Path) -> None:
    result = _run(str(TRIVY), "--offline", "--cache-dir", str(tmp_path), "--format", "json")
    assert result.exit_code == EXIT_OK
    assert "offline: no cached KEV catalog" in result.stderr
    assert _ranked(json.loads(result.stdout))[0][0] == "P3"


# --- Logging and version ---------------------------------------------------------------------


def test_verbose_shows_info_logs_on_stderr() -> None:
    result = _run(str(TRIVY), *LOCAL_INTEL, "-v")
    assert "GHSA-aaaa-bbbb-cccc" in result.stderr


def test_quiet_hides_warnings() -> None:
    result = _run(str(TRIVY), *LOCAL_INTEL, "-q")
    assert "malformed" not in result.stderr


def test_version() -> None:
    result = _run("--version")
    assert result.exit_code == EXIT_OK
    assert result.stdout.strip() == f"vulnrank {__version__}"
