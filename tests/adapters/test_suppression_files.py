import logging
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from vulnrank.adapters.suppressions.openvex import load_openvex
from vulnrank.adapters.suppressions.trivyignore import load_trivyignore
from vulnrank.domain.suppression import VexProduct, VexStatus
from vulnrank.ports.sources import SourceError

FIXTURES = Path(__file__).parents[1] / "fixtures" / "vex"


# --- OpenVEX -------------------------------------------------------------------------------------


def test_openvex_statements_are_read(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="vulnrank"):
        statements = load_openvex(FIXTURES / "openvex.json")
    first, second, third = statements
    assert first.vuln_ids == ("CVE-2023-0002", "GHSA-demo-demo-demo")
    assert first.products == (
        VexProduct(
            purl="pkg:oci/demo-app",
            subcomponents=("pkg:deb/debian/libssl3", "pkg:deb/debian/openssl"),
        ),
    )
    assert first.timestamp == datetime(2026, 9, 2, 8, 0, tzinfo=UTC)  # the statement's own
    assert second.timestamp == datetime(2026, 9, 1, 10, 0, tzinfo=UTC)  # the document's
    assert (first.status, first.justification) == (
        VexStatus.NOT_AFFECTED,
        "vulnerable_code_not_in_execute_path",
    )
    assert first.source == "openvex.json"
    assert (second.status, second.products) == (VexStatus.UNDER_INVESTIGATION, ())
    assert (third.vuln_ids, third.status) == (("CVE-2023-0009",), VexStatus.FIXED)  # v0.0.x form
    assert third.products == (VexProduct(purl="pkg:oci/demo-app"),)
    assert "statements[3]" in caplog.text  # unknown status
    assert "statements[4]" in caplog.text  # not an object
    assert "statements[5]" in caplog.text  # not_affected without justification or impact


@pytest.mark.parametrize(
    ("content", "message"),
    [('{"hello": 1}', "not an OpenVEX document"), ("{not json", "not valid JSON")],
)
def test_a_file_that_is_not_openvex_is_a_source_error(
    tmp_path: Path, content: str, message: str
) -> None:
    path = tmp_path / "vex.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(SourceError, match=message):
        load_openvex(path)


# --- .trivyignore -------------------------------------------------------------------------------


def test_trivyignore_ids_expiry_and_comment_reasons(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="vulnrank"):
        rules = load_trivyignore(FIXTURES / "trivyignore")
    assert [(r.vuln_id, r.expires, r.reason) for r in rules] == [
        ("CVE-2023-0001", None, "Only reachable through the admin UI, which is not deployed"),
        ("CVE-2023-0003", date(2026, 12, 31), "Accepted until the base image upgrade"),
        ("CVE-2023-0004", None, "listed in trivyignore"),
    ]
    assert {r.source for r in rules} == {"trivyignore"}
    assert "exp:not-a-date" in caplog.text


def test_missing_trivyignore_is_a_source_error(tmp_path: Path) -> None:
    with pytest.raises(SourceError, match="cannot read"):
        load_trivyignore(tmp_path / ".trivyignore")


def test_unknown_trivyignore_options_are_ignored(tmp_path: Path) -> None:
    path = tmp_path / ".trivyignore"
    path.write_text("CVE-2023-0006 future-option\n", encoding="utf-8")
    [rule] = load_trivyignore(path)
    assert (rule.vuln_id, rule.expires) == ("CVE-2023-0006", None)
