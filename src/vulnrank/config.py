"""The user's config file: asset context and scoring thresholds, in TOML.

Example:

    [scoring]
    p2_epss = 0.2

    [default_asset]
    criticality = "medium"

    [[assets]]
    target = "shop-frontend"      # matches any tag: shop-frontend:2.4, shop-frontend@sha256:…
    criticality = "critical"
    internet_exposed = true

    [[assets]]
    target = "ghcr.io/acme/*"     # glob patterns are tried in file order
    criticality = "high"

A scan target is matched by its exact name first, then by its name without tag or digest,
then against glob patterns in the order they appear.
"""

import tomllib
from collections import Counter
from fnmatch import fnmatchcase
from pathlib import Path

from pydantic import Field, ValidationError, field_validator

from vulnrank.domain.models import Asset, Criticality, DomainModel
from vulnrank.domain.policy import ScoringPolicy
from vulnrank.domain.targets import image_repository


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

    def match_asset(self, target: str) -> Asset | None:
        """The configured asset for a scan target, reported under the scanned name."""
        repository = image_repository(target)
        match = (
            next((a for a in self.assets if a.target == target), None)
            or next((a for a in self.assets if a.target == repository), None)
            or next(
                (
                    a
                    for a in self.assets
                    if fnmatchcase(target, a.target) or fnmatchcase(repository, a.target)
                ),
                None,
            )
        )
        return None if match is None else match.model_copy(update={"target": target})

    def asset_for(self, target: str) -> Asset:
        return self.match_asset(target) or Asset(
            target=target,
            criticality=self.default_asset.criticality,
            internet_exposed=self.default_asset.internet_exposed,
        )


def load_config(path: Path) -> Config:
    try:
        data = tomllib.loads(path.read_bytes().decode("utf-8-sig"))
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc.strerror}") from exc
    except UnicodeDecodeError as exc:
        raise ConfigError(f"config file {path} is not valid UTF-8 ({exc.reason})") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
    try:
        return Config.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"invalid config in {path}:\n{exc}") from exc
