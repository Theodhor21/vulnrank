"""End-to-end: run the real CLI against fixture files. No network (see conftest)."""

import json
import logging
import re
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


ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    """CI forces colour output; compare against the text without escape codes."""
    return ANSI_ESCAPE.sub("", text)


def _run(*args: str) -> Result:
    return CliRunner().invoke(app, list(args), env={"COLUMNS": "200"})


def _json(*args: str) -> dict[str, Any]:
    result = _run(*args, "--format", "json")
    assert result.exit_code == EXIT_OK, result.output
    return json.loads(result.stdout)


def _ranked(document: dict[str, Any]) -> list[tuple[str, str, str]]:
    return [(f["priority"], f["id"], f["component"]["name"]) for f in document["findings"]]


# --- Happy path ------------------------------------------------------------------------------


def test_scan_is_ranked_with_asset_context() -> None:
    assert _ranked(_json(str(TRIVY), *ASSETS, *LOCAL_INTEL)) == [
        ("P1", "CVE-2023-0001", "openssl"),  # in KEV
        ("P2", "CVE-2023-0002", "libssl3"),  # CVSS 9.8 on a critical asset
        ("P2", "CVE-2023-0002", "openssl"),
        ("P4", "CVE-2023-0003", "requests"),
        ("P4", "GHSA-aaaa-bbbb-cccc", "urllib3"),  # no CVE: ranked without EPSS/KEV
    ]


def test_without_asset_config_the_default_criticality_applies() -> None:
    ranked = _ranked(_json(str(TRIVY), *LOCAL_INTEL))
    assert [priority for priority, _, _ in ranked] == ["P1", "P3", "P3", "P4", "P4"]


def test_both_input_formats_give_the_same_result() -> None:
    def without_fix_status(document: dict[str, Any]) -> list[dict[str, Any]]:
        # CycloneDX has no field for Trivy's vendor fix status.
        return [{k: v for k, v in f.items() if k != "fix_status"} for f in document["findings"]]

    from_trivy = _json(str(TRIVY), *ASSETS, *LOCAL_INTEL)
    from_cyclonedx = _json(str(CYCLONEDX), *ASSETS, *LOCAL_INTEL)
    assert without_fix_status(from_trivy) == without_fix_status(from_cyclonedx)


def test_table_is_the_default_format() -> None:
    result = _run(str(TRIVY), *ASSETS, *LOCAL_INTEL)
    assert result.exit_code == EXIT_OK
    assert "vulnrank: demo-app:1.0" in _plain(result.stdout)
    assert "in CISA KEV (added 2024-01-10)" in _plain(result.stdout)
    assert "P1: 1 · P2: 2 · P3: 0 · P4: 2" in _plain(result.stdout)


def test_markdown_format() -> None:
    result = _run(str(TRIVY), *LOCAL_INTEL, "--format", "markdown")
    assert _plain(result.stdout).startswith("## vulnrank: demo-app:1.0")


def test_sarif_format_for_github_code_scanning() -> None:
    result = _run(str(TRIVY), *ASSETS, *LOCAL_INTEL, "--format", "sarif", "--top", "0")
    assert result.exit_code == EXIT_OK
    document = json.loads(result.stdout)
    assert document["version"] == "2.1.0"
    [run] = document["runs"]
    assert [r["ruleId"] for r in run["results"]] == [
        "CVE-2023-0001",
        "CVE-2023-0002",
        "CVE-2023-0002",
        "CVE-2023-0003",
        "GHSA-aaaa-bbbb-cccc",
    ]
    uri = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "demo-app"


def test_sarif_uri_points_alerts_at_a_repository_file() -> None:
    args = ["--format", "sarif", "--sarif-uri", "docker/Dockerfile"]
    result = _run(str(TRIVY), *LOCAL_INTEL, *args)
    [run] = json.loads(result.stdout)["runs"]
    uris = {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"]
    }
    assert uris == {"docker/Dockerfile"}


@pytest.mark.parametrize(("top", "listed"), [("1", 1), ("0", 5), ("99", 5)])
def test_top_limits_the_listed_findings(top: str, listed: int) -> None:
    document = _json(str(TRIVY), *LOCAL_INTEL, "--top", top)
    assert len(document["findings"]) == listed


def test_report_can_be_written_to_a_file(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    result = _run(str(TRIVY), *LOCAL_INTEL, "--format", "json", "--output", str(out))
    assert result.exit_code == EXIT_OK
    assert result.stdout == ""
    assert json.loads(out.read_text(encoding="utf-8"))["summary"]["unique_findings"] == 5


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
    assert message in _plain(result.stderr)


def test_unwritable_output_exits_2(tmp_path: Path) -> None:
    result = _run(str(TRIVY), *LOCAL_INTEL, "--output", str(tmp_path / "no" / "dir.json"))
    assert result.exit_code == EXIT_ERROR
    assert "error:" in _plain(result.stderr)


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
    assert "offline: no cached KEV catalog" in _plain(result.stderr)
    assert _ranked(json.loads(result.stdout))[0][0] == "P3"


# --- Logging and version ---------------------------------------------------------------------


def test_verbose_shows_info_logs_on_stderr() -> None:
    result = _run(str(TRIVY), *LOCAL_INTEL, "-v")
    assert "loaded 5 findings from 5 records" in _plain(result.stderr)


def test_quiet_hides_warnings() -> None:
    result = _run(str(TRIVY), *LOCAL_INTEL, "-q")
    assert "malformed" not in _plain(result.stderr)


def test_version() -> None:
    result = _run("--version")
    assert result.exit_code == EXIT_OK
    assert result.stdout.strip() == f"vulnrank {__version__}"


def test_verbose_and_quiet_together_is_a_usage_error() -> None:
    result = _run(str(TRIVY), *LOCAL_INTEL, "-v", "-q")
    assert result.exit_code == EXIT_ERROR
    assert "--verbose and --quiet" in _plain(result.output)


# --- Robustness: a crash must never look like "findings found" --------------------------------


def test_an_unexpected_error_exits_2_not_1(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr("vulnrank.cli.prioritise", explode)
    result = _run(str(TRIVY), *LOCAL_INTEL, "--fail-on", "P1")
    assert result.exit_code == EXIT_ERROR
    assert "internal error: boom" in _plain(result.stderr)


def test_a_utf16_scan_is_accepted(tmp_path: Path) -> None:
    """What PowerShell's `>` redirection writes on Windows."""
    scan = tmp_path / "scan.json"
    scan.write_bytes(TRIVY.read_text(encoding="utf-8").encode("utf-16"))
    assert len(_json(str(scan), *LOCAL_INTEL)["findings"]) == 5


def test_an_undecodable_scan_exits_2(tmp_path: Path) -> None:
    scan = tmp_path / "scan.json"
    scan.write_bytes('{"SchemaVersion": 2, "ArtifactName": "café"}'.encode("latin-1"))
    result = _run(str(scan), *LOCAL_INTEL)
    assert result.exit_code == EXIT_ERROR
    assert "not valid UTF-8 or UTF-16" in _plain(result.stderr)


# --- Asset matching ------------------------------------------------------------------------------


def test_a_warning_names_targets_that_no_asset_entry_matches() -> None:
    result = _run(str(TRIVY), *LOCAL_INTEL, "--assets", str(FIXTURES / "assets.toml"))
    assert result.exit_code == EXIT_OK
    assert "no [[assets]] entry matches 'demo-app:1.0'" in _plain(result.stderr)


def test_no_warning_without_an_assets_file() -> None:
    assert "[[assets]]" not in _plain(_run(str(TRIVY), *LOCAL_INTEL).stderr)


def test_an_asset_without_a_tag_matches_every_tag(tmp_path: Path) -> None:
    assets = tmp_path / "assets.toml"
    assets.write_text(
        '[[assets]]\ntarget = "demo-app"\ncriticality = "critical"\ninternet_exposed = true\n',
        encoding="utf-8",
    )
    ranked = _ranked(_json(str(TRIVY), *LOCAL_INTEL, "--assets", str(assets)))
    assert [p for p, _, _ in ranked] == ["P1", "P2", "P2", "P4", "P4"]


def test_target_overrides_the_name_from_the_scan() -> None:
    args = ["--assets", str(FIXTURES / "assets.toml"), "--target", "shop-frontend:2.4"]
    document = _json(str(TRIVY), *LOCAL_INTEL, *args)
    assert {f["target"] for f in document["findings"]} == {"shop-frontend:2.4"}
    assert document["findings"][0]["asset"]["criticality"] == "critical"


# --- Strict mode: missing threat intelligence fails the gate -------------------------------------


def test_strict_fails_when_enrichment_is_incomplete(tmp_path: Path) -> None:
    result = _run(str(TRIVY), "--offline", "--cache-dir", str(tmp_path), "--strict")
    assert result.exit_code == EXIT_ERROR
    assert "enrichment incomplete" in _plain(result.stderr)


def test_strict_passes_when_enrichment_is_complete() -> None:
    assert _run(str(TRIVY), *LOCAL_INTEL, "--strict").exit_code == EXIT_OK


def test_without_strict_incomplete_enrichment_is_reported_but_not_fatal(tmp_path: Path) -> None:
    result = _run(str(TRIVY), "--offline", "--cache-dir", str(tmp_path), "--format", "json")
    assert result.exit_code == EXIT_OK
    issues = json.loads(result.stdout)["summary"]["enrichment_issues"]
    assert issues == [
        "offline: no cached EPSS score for 3 CVE(s)",
        "offline: no cached KEV catalog",
    ]


# --- Fix plan view ------------------------------------------------------------------------------


def test_fix_view_groups_findings_into_upgrades() -> None:
    result = _run(str(TRIVY), *ASSETS, *LOCAL_INTEL, "--view", "fixes")
    assert result.exit_code == EXIT_OK
    text = _plain(result.stdout)
    assert "vulnrank fix plan: demo-app:1.0" in text
    assert text.index("openssl") < text.index("libssl3") < text.index("urllib3")
    assert "3 upgrades cover 4 findings; 1 finding has no fix (1 not yet fixed)" in text


def test_json_carries_the_fix_plan_in_either_view() -> None:
    document = _json(str(TRIVY), *ASSETS, *LOCAL_INTEL)
    first = document["fix_plan"]["actions"][0]
    assert (first["packages"], first["fixed_version"], first["priority"]) == (
        ["openssl"],
        "3.0.12-1",
        "P1",
    )


def test_fix_view_is_not_available_for_sarif() -> None:
    result = _run(str(TRIVY), *LOCAL_INTEL, "--view", "fixes", "--format", "sarif")
    assert result.exit_code == EXIT_ERROR
    assert "--view fixes" in _plain(result.output)


# --- Suppression -------------------------------------------------------------------------------


def test_ignore_file_suppresses_and_warns_about_kev(tmp_path: Path) -> None:
    ignore = tmp_path / ".trivyignore"
    ignore.write_text("# admin UI not deployed\nCVE-2023-0001\n", encoding="utf-8")
    result = _run(str(TRIVY), *LOCAL_INTEL, "--ignore-file", str(ignore), "--format", "json")
    assert result.exit_code == EXIT_OK
    document = json.loads(result.stdout)
    assert "CVE-2023-0001" not in {f["id"] for f in document["findings"]}
    assert document["suppressed"][0]["reason"] == "admin UI not deployed"
    assert "suppressed CVE-2023-0001 is in CISA KEV" in _plain(result.stderr)


def test_vex_file_suppresses(tmp_path: Path) -> None:
    vex = FIXTURES / "vex" / "openvex.json"
    document = _json(str(TRIVY), *LOCAL_INTEL, "--vex", str(vex))
    ids = [(f["id"], f["component"]["name"]) for f in document["findings"]]
    assert ("CVE-2023-0002", "openssl") not in ids
    assert ("CVE-2023-0002", "libssl3") not in ids
    assert document["summary"]["suppressed"] == 2


def test_suppressed_findings_do_not_trip_the_gate(tmp_path: Path) -> None:
    ignore = tmp_path / ".trivyignore"
    ignore.write_text("CVE-2023-0001\n", encoding="utf-8")
    args = ["--ignore-file", str(ignore), "--fail-on", "P1", "-q"]
    assert _run(str(TRIVY), *LOCAL_INTEL, *args).exit_code == EXIT_OK


def test_ignore_rules_from_the_assets_file(tmp_path: Path) -> None:
    assets = tmp_path / "assets.toml"
    assets.write_text(
        '[[ignore]]\npackage = "urllib3"\nreason = "vendored, unused"\n', encoding="utf-8"
    )
    document = _json(str(TRIVY), *LOCAL_INTEL, "--assets", str(assets))
    assert document["suppressed"][0]["component"] == "urllib3"


# --- Baseline gating --------------------------------------------------------------------------


def _baseline(tmp_path: Path, *args: str) -> Path:
    path = tmp_path / "baseline.json"
    result = _run(
        str(TRIVY), *LOCAL_INTEL, *args, "--format", "json", "--top", "0", "-o", str(path)
    )
    assert result.exit_code == EXIT_OK
    return path


def test_known_findings_do_not_trip_the_gate_against_a_baseline(tmp_path: Path) -> None:
    baseline = _baseline(tmp_path)
    assert _run(str(TRIVY), *LOCAL_INTEL, "--fail-on", "P1").exit_code == EXIT_FINDINGS
    args = ["--baseline", str(baseline), "--fail-on", "P1"]
    assert _run(str(TRIVY), *LOCAL_INTEL, *args).exit_code == EXIT_OK


def test_an_escalated_finding_trips_the_gate(tmp_path: Path) -> None:
    baseline = _baseline(tmp_path)  # without asset context: CVE-2023-0002 was P3
    args = [*ASSETS, "--baseline", str(baseline)]  # critical asset: now P2
    result = _run(str(TRIVY), *LOCAL_INTEL, *args, "--fail-on", "P2")
    assert result.exit_code == EXIT_FINDINGS
    assert "↑ from P3" in _plain(result.stdout)
    assert _run(str(TRIVY), *LOCAL_INTEL, *args, "--fail-on", "P1").exit_code == EXIT_OK


def test_an_incomplete_baseline_is_warned_about(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    _run(str(TRIVY), *LOCAL_INTEL, "--format", "json", "--top", "1", "-o", str(path))
    result = _run(str(TRIVY), *LOCAL_INTEL, "--baseline", str(path))
    assert "baseline does not list every finding" in _plain(result.stderr)


def test_a_bad_baseline_exits_2(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text("{}", encoding="utf-8")
    result = _run(str(TRIVY), *LOCAL_INTEL, "--baseline", str(path))
    assert result.exit_code == EXIT_ERROR
    assert "vulnrank JSON report" in _plain(result.stderr)


# --- Grype input ---------------------------------------------------------------------------------


def test_a_grype_report_gives_the_same_ranking_as_trivy() -> None:
    from_trivy = _json(str(TRIVY), *ASSETS, *LOCAL_INTEL)
    from_grype = _json(str(FIXTURES / "grype" / "basic.json"), *ASSETS, *LOCAL_INTEL)
    assert from_grype["findings"] == from_trivy["findings"]
