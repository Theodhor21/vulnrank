"""The user's config file: asset context and scoring thresholds, in TOML.

Example:

    [scoring]
    p2_epss = 0.2

    [default_asset]
    criticality = "medium"

    [[assets]]
    target = "shop-frontend:2.4"
    criticality = "critical"
    internet_exposed = true
"""

import tomllib
from collections import Counter
from pathlib import Path

from pydantic import Field, ValidationError, field_validator

from vulnrank.domain.models import Asset, Criticality, DomainModel
from vulnrank.domain.policy import ScoringPolicy


class ConfigError(Exception):
    """The config file is missing, unreadable or invalid."""


class AssetDefaults(DomainModel):
    """Context applied to scan targets that are not listed under [[assets]]."""

    criticality: Criticality = Criticality.MEDIUM
    internet_exposed: bool = False


class Config(DomainModel):
    scoring: ScoringPolicy = Field(default_factory=ScoringPolicy)
    default_asset: AssetDefaults = Field(default_factory=AssetDefaults)
    assets: tuple[Asset, ...] = ()

    @field_validator("assets")
    @classmethod
    def _targets_are_unique(cls, assets: tuple[Asset, ...]) -> tuple[Asset, ...]:
        counts = Counter(asset.target for asset in assets)
        duplicates = sorted(target for target, count in counts.items() if count > 1)
        if duplicates:
            raise ValueError(f"duplicate asset targets: {', '.join(duplicates)}")
        return assets

    def asset_for(self, target: str) -> Asset:
        for asset in self.assets:
            if asset.target == target:
                return asset
        return Asset(
            target=target,
            criticality=self.default_asset.criticality,
            internet_exposed=self.default_asset.internet_exposed,
        )


def load_config(path: Path) -> Config:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc.strerror}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
    try:
        return Config.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"invalid config in {path}:\n{exc}") from exc
