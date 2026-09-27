import re
from datetime import date
from pathlib import Path

import pytest

from vulnrank.config import Config, ConfigError, load_config
from vulnrank.domain.models import Asset, Criticality
from vulnrank.domain.policy import ScoringPolicy

FIXTURES = Path(__file__).parent / "fixtures"


def _write(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "assets.toml"
    path.write_text(content, encoding="utf-8")
    return path


def test_empty_file_gives_defaults(tmp_path: Path) -> None:
    config = load_config(_write(tmp_path, ""))
    assert config == Config()
    assert config.scoring == ScoringPolicy()


def test_full_example_is_loaded() -> None:
    config = load_config(FIXTURES / "assets.toml")
    assert config.scoring.p2_epss == 0.2
    assert config.scoring.p3_cvss == 7.0  # not set in the file, default kept
    assert config.default_asset.criticality is Criticality.LOW
    assert config.assets == (
        Asset(target="shop-frontend:2.4", criticality=Criticality.CRITICAL, internet_exposed=True),
        Asset(target="batch-worker:1.0", criticality=Criticality.HIGH),
    )


def test_listed_asset_is_returned_by_target() -> None:
    config = load_config(FIXTURES / "assets.toml")
    assert config.asset_for("shop-frontend:2.4").internet_exposed is True


def test_unlisted_target_gets_the_defaults() -> None:
    config = load_config(FIXTURES / "assets.toml")
    assert config.asset_for("unknown:latest") == Asset(
        target="unknown:latest", criticality=Criticality.LOW, internet_exposed=False
    )


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("[scoring]\np2_epss = 1.5\n", "p2_epss"),
        ("[scoring]\np3_cvss = 11\n", "p3_cvss"),
        ('[[assets]]\ntarget = "a"\ncriticality = "extreme"\n', "criticality"),
        ('[[assets]]\ntarget = "a"\n\n[[assets]]\ntarget = "a"\n', "duplicate asset targets: a"),
        ("[scoring]\np2_epsss = 0.2\n", "p2_epsss"),
        ("[[assets]]\ncriticality = 'high'\n", "target"),
        (
            "[scoring]\np1_epss_on_high_criticality = 0.05\n",
            "p1_epss_on_high_criticality (0.05) must be ≥ p2_epss (0.1)",
        ),
        (
            "[scoring]\np2_cvss_on_high_criticality = 6.0\n",
            "p2_cvss_on_high_criticality (6.0) must be ≥ p3_cvss (7.0)",
        ),
    ],
    ids=[
        "epss-range",
        "cvss-range",
        "bad-criticality",
        "duplicate",
        "typo",
        "missing-target",
        "p1-epss-below-p2",
        "p2-cvss-below-p3",
    ],
)
def test_invalid_config_is_rejected_with_a_clear_message(
    tmp_path: Path, content: str, message: str
) -> None:
    with pytest.raises(ConfigError, match=re.escape(message)):
        load_config(_write(tmp_path, content))


def test_invalid_toml_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(_write(tmp_path, "[scoring\n"))


def test_missing_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read config file"):
        load_config(tmp_path / "nope.toml")


# --- Asset matching ------------------------------------------------------------------------------

MATCHING = """
[[assets]]
target = "shop-frontend:2.4"
criticality = "critical"

[[assets]]
target = "shop-*"
criticality = "high"

[[assets]]
target = "*"
criticality = "low"

[[assets]]
target = "billing"
criticality = "critical"
internet_exposed = true
"""


@pytest.mark.parametrize(
    ("target", "criticality"),
    [
        pytest.param("shop-frontend:2.4", Criticality.CRITICAL, id="exact-match-wins"),
        pytest.param("shop-frontend:3.0", Criticality.HIGH, id="first-glob-in-file-order"),
        pytest.param("billing:9f3c2a1", Criticality.CRITICAL, id="tag-is-ignored"),
        pytest.param("billing@sha256:0123abcd", Criticality.CRITICAL, id="digest-is-ignored"),
        pytest.param("other:1.0", Criticality.LOW, id="catch-all-glob"),
    ],
)
def test_assets_match_by_name_repository_or_glob(
    tmp_path: Path, target: str, criticality: Criticality
) -> None:
    config = load_config(_write(tmp_path, MATCHING))
    asset = config.asset_for(target)
    assert asset.criticality is criticality
    assert asset.target == target  # the asset is reported under the scanned name


def test_match_asset_is_none_when_nothing_matches() -> None:
    config = load_config(FIXTURES / "assets.toml")
    assert config.match_asset("unknown:latest") is None
    assert config.match_asset("batch-worker:1.0") is not None


# --- Encodings -----------------------------------------------------------------------------------


def test_a_utf8_bom_is_accepted(tmp_path: Path) -> None:
    path = tmp_path / "assets.toml"
    path.write_bytes("[scoring]\np2_epss = 0.2\n".encode("utf-8-sig"))
    assert load_config(path).scoring.p2_epss == 0.2


def test_undecodable_config_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "assets.toml"
    path.write_bytes('[[assets]]\ntarget = "café"\n'.encode("latin-1"))
    with pytest.raises(ConfigError, match="not valid UTF-8"):
        load_config(path)


# --- Ignore rules ---------------------------------------------------------------------------------


def test_ignore_rules_are_loaded(tmp_path: Path) -> None:
    config = load_config(
        _write(
            tmp_path,
            """
[[ignore]]
package = "linux-libc-dev"
reason = "kernel headers; containers use the host kernel"

[[ignore]]
id = "CVE-2023-0001"
target = "demo-*"
reason = "not exposed"
expires = 2026-12-31
""",
        )
    )
    first, second = config.ignore
    assert (first.package, first.vuln_id, first.source) == (
        "linux-libc-dev",
        None,
        str(tmp_path / "assets.toml"),
    )
    assert (second.vuln_id, second.target, second.expires) == (
        "CVE-2023-0001",
        "demo-*",
        date(2026, 12, 31),
    )


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ('[[ignore]]\nid = "CVE-2023-0001"\n', "reason"),
        ('[[ignore]]\ntarget = "x"\nreason = "r"\n', "needs an id or a package"),
    ],
)
def test_invalid_ignore_rules_are_rejected(tmp_path: Path, content: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        load_config(_write(tmp_path, content))
