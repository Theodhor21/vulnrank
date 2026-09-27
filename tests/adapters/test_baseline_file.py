import io
import json
import logging
from pathlib import Path

import pytest

from tests.builders import make_scored
from vulnrank.adapters.inputs.baseline import load_baseline
from vulnrank.adapters.outputs.json_report import JsonReporter
from vulnrank.domain.models import Priority, Report
from vulnrank.ports.sources import SourceError

REPORT = Report(
    findings=(
        make_scored(priority=Priority.P1, vuln_id="CVE-2024-0001", target="app:1.0"),
        make_scored(priority=Priority.P3, vuln_id="CVE-2024-0002", target="app:1.0"),
    ),
    scanned=2,
    duplicates_removed=0,
)


def _write(tmp_path: Path, report: Report = REPORT, limit: int | None = None) -> Path:
    out = io.StringIO()
    JsonReporter().write(report, out, limit=limit)
    path = tmp_path / "baseline.json"
    path.write_text(out.getvalue(), encoding="utf-8")
    return path


def test_a_vulnrank_json_report_is_a_baseline(tmp_path: Path) -> None:
    baseline = load_baseline(_write(tmp_path))
    assert baseline.priorities == {
        ("app", "openssl", "CVE-2024-0001"): Priority.P1,
        ("app", "openssl", "CVE-2024-0002"): Priority.P3,
    }
    assert baseline.complete is True


def test_a_report_cut_by_top_is_an_incomplete_baseline(tmp_path: Path) -> None:
    assert load_baseline(_write(tmp_path, limit=1)).complete is False


def test_malformed_entries_are_skipped(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    path = _write(tmp_path)
    document = json.loads(path.read_text(encoding="utf-8"))
    document["findings"].append({"id": "CVE-2024-0003"})
    path.write_text(json.dumps(document), encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="vulnrank"):
        assert len(load_baseline(path).priorities) == 2
    assert "findings[2]" in caplog.text


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ('{"schema_version": 1, "findings": []}', "vulnrank JSON report"),
        ('{"hello": 1}', "vulnrank JSON report"),
        ("[1, 2]", "vulnrank JSON report"),
    ],
)
def test_other_documents_are_not_baselines(tmp_path: Path, content: str, message: str) -> None:
    path = tmp_path / "baseline.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(SourceError, match=message):
        load_baseline(path)
