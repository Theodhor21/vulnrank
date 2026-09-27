"""Compare package versions well enough to pick the right upgrade.

Debian packages use dpkg's exact algorithm: epoch, then upstream version, then revision,
where `~` sorts before everything (so `1.2.3~rc1` < `1.2.3`). Other ecosystems use a generic
comparison: numbers compare as numbers, and a known pre-release word (alpha, beta, rc,
snapshot, ...) makes a version older than its release, as in SemVer, PEP 440 and Maven.
Words that are not pre-releases, such as Alpine's `-r1` revision or Python's `.post1`,
make a version newer.
"""

import re
from collections.abc import Iterable
from functools import reduce
from typing import Final

DPKG_ECOSYSTEMS: Final = frozenset({"deb", "debian", "ubuntu"})

# Ranks below any release; a lower rank is older. Unknown words rank after the release.
PRE_RELEASE_RANK: Final = {
    "dev": 0,
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "milestone": 3,
    "m": 3,
    "pre": 4,
    "preview": 4,
    "rc": 5,
    "c": 5,
    "cr": 5,
    "snapshot": 6,
}

_TOKENS = re.compile(r"\d+|[A-Za-z]+")


def compare_versions(a: str, b: str, ecosystem: str | None) -> int:
    """Negative if `a` is older than `b`, zero if equal, positive if newer."""
    if ecosystem in DPKG_ECOSYSTEMS:
        return _compare_dpkg(a, b)
    return _compare_generic(a, b)


def fix_target(installed: str, fixed: str, ecosystem: str | None) -> str:
    """The smallest listed fix above the installed version.

    Trivy lists one fixed version per release branch, e.g. `"3.0.8, 3.1.2"`. Upgrading
    3.1.0 needs 3.1.2 (its own branch), not 3.0.8 and not the highest listed.
    """
    candidates = [part.strip() for part in fixed.split(",") if part.strip()]
    above = [c for c in candidates if compare_versions(c, installed, ecosystem) > 0]
    if above:
        return oldest_version(above, ecosystem)
    return newest_version(candidates, ecosystem) if candidates else fixed.strip()


def newest_version(versions: Iterable[str], ecosystem: str | None) -> str:
    """The newest of a non-empty collection of versions."""

    def newer(a: str, b: str) -> str:
        return b if compare_versions(b, a, ecosystem) > 0 else a

    return reduce(newer, versions)


def oldest_version(versions: Iterable[str], ecosystem: str | None) -> str:
    """The oldest of a non-empty collection of versions."""

    def older(a: str, b: str) -> str:
        return b if compare_versions(b, a, ecosystem) < 0 else a

    return reduce(older, versions)


# --- dpkg ------------------------------------------------------------------------------------


def _compare_dpkg(a: str, b: str) -> int:
    epoch_a, upstream_a, revision_a = _split_dpkg(a)
    epoch_b, upstream_b, revision_b = _split_dpkg(b)
    if epoch_a != epoch_b:
        return epoch_a - epoch_b
    return _verrevcmp(upstream_a, upstream_b) or _verrevcmp(revision_a, revision_b)


def _split_dpkg(version: str) -> tuple[int, str, str]:
    epoch, colon, rest = version.partition(":")
    if not colon or not epoch.isdigit():
        epoch, rest = "0", version
    upstream, dash, revision = rest.rpartition("-")
    if not dash:
        upstream, revision = rest, ""
    return int(epoch), upstream, revision


def _order(char: str) -> int:
    """dpkg's character order: `~` first, then the end of the string, letters, then symbols."""
    if not char or char.isdigit():
        return 0
    if char == "~":
        return -1
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _verrevcmp(a: str, b: str) -> int:
    """A port of dpkg's verrevcmp()."""
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i] if i < len(a) else "")
            bc = _order(b[j] if j < len(b) else "")
            if ac != bc:
                return ac - bc
            i, j = i + 1, j + 1
        number_a, i = _number(a, i)
        number_b, j = _number(b, j)
        if number_a != number_b:
            return number_a - number_b
    return 0


def _number(text: str, start: int) -> tuple[int, int]:
    end = start
    while end < len(text) and text[end].isdigit():
        end += 1
    return int(text[start:end] or 0), end


# --- Generic -----------------------------------------------------------------------------------


def _compare_generic(a: str, b: str) -> int:
    tokens_a, tokens_b = _TOKENS.findall(a.lower()), _TOKENS.findall(b.lower())
    for token_a, token_b in zip(tokens_a, tokens_b, strict=False):
        if (difference := _compare_tokens(token_a, token_b)) != 0:
            return difference
    if len(tokens_a) == len(tokens_b):
        return 0
    # One version continues: a pre-release word makes it older, anything else newer.
    longer_is_a = len(tokens_a) > len(tokens_b)
    extra = (tokens_a if longer_is_a else tokens_b)[min(len(tokens_a), len(tokens_b))]
    newer = extra not in PRE_RELEASE_RANK
    return 1 if newer == longer_is_a else -1


def _compare_tokens(a: str, b: str) -> int:
    if a.isdigit() and b.isdigit():
        return int(a) - int(b)
    if a.isdigit() != b.isdigit():
        return 1 if a.isdigit() else -1  # a number outranks a word (1.0.1 > 1.0.beta)
    rank_a, rank_b = _word_rank(a), _word_rank(b)
    if rank_a != rank_b:
        return rank_a - rank_b
    return (a > b) - (a < b)


def _word_rank(word: str) -> int:
    """Pre-release words rank by maturity; any other word ranks after all of them."""
    return PRE_RELEASE_RANK.get(word, len(PRE_RELEASE_RANK))
