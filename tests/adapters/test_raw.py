from pathlib import Path

import pytest

from vulnrank.adapters._raw import read_json, read_text
from vulnrank.ports.sources import SourceError

DOCUMENT = '{"SchemaVersion": 2, "ArtifactName": "café:1.0"}'
EXPECTED = {"SchemaVersion": 2, "ArtifactName": "café:1.0"}


@pytest.mark.parametrize(
    "encoded",
    [
        pytest.param(DOCUMENT.encode("utf-8"), id="utf-8"),
        pytest.param(DOCUMENT.encode("utf-8-sig"), id="utf-8-with-bom"),
        # What PowerShell's `>` redirection writes on Windows.
        pytest.param(DOCUMENT.encode("utf-16"), id="utf-16-with-bom"),
        pytest.param(b"\xfe\xff" + DOCUMENT.encode("utf-16-be"), id="utf-16-be-with-bom"),
    ],
)
def test_common_encodings_are_read(tmp_path: Path, encoded: bytes) -> None:
    path = tmp_path / "scan.json"
    path.write_bytes(encoded)
    assert read_json(path) == EXPECTED


def test_undecodable_bytes_are_a_source_error(tmp_path: Path) -> None:
    path = tmp_path / "scan.json"
    path.write_bytes(DOCUMENT.encode("latin-1"))
    with pytest.raises(SourceError, match="not valid UTF-8 or UTF-16"):
        read_json(path)


def test_read_text_strips_a_utf8_bom(tmp_path: Path) -> None:
    path = tmp_path / "file.txt"
    path.write_bytes("﻿hello".encode())
    assert read_text(path) == "hello"
