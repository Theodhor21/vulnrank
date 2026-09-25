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
    ],
    ids=["epss-range", "cvss-range", "bad-criticality", "duplicate", "typo", "missing-target"],
)
def test_invalid_config_is_rejected_with_a_clear_message(
    tmp_path: Path, content: str, message: str
) -> None:
    with pytest.raises(ConfigError, match=message):
        load_config(_write(tmp_path, content))


def test_invalid_toml_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(_write(tmp_path, "[scoring\n"))


def test_missing_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read config file"):
        load_config(tmp_path / "nope.toml")
