"""Read Trivy's `.trivyignore`: one ID per line, optional `exp:YYYY-MM-DD`, `#` comments.

The comment block right above an ID is used as its reason, following Trivy's own examples.
"""

import logging
from datetime import date
from pathlib import Path

from vulnrank.adapters._raw import read_text
from vulnrank.domain.suppression import IgnoreRule

logger = logging.getLogger(__name__)


def load_trivyignore(path: Path) -> tuple[IgnoreRule, ...]:
    rules: list[IgnoreRule] = []
    comment: list[str] = []
    for number, raw_line in enumerate(read_text(path).splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            comment = []
        elif line.startswith("#"):
            comment.append(line.lstrip("#").strip())
        elif (rule := _rule(line, " ".join(comment), path, number)) is not None:
            rules.append(rule)
    return tuple(rules)


def _rule(line: str, comment: str, path: Path, number: int) -> IgnoreRule | None:
    vuln_id, *options = line.split()
    expires: date | None = None
    for option in options:
        if option.startswith("exp:"):
            try:
                expires = date.fromisoformat(option.removeprefix("exp:"))
            except ValueError:
                logger.warning("skipping %s line %d: invalid expiry %r", path, number, option)
                return None
    return IgnoreRule(
        vuln_id=vuln_id,
        reason=comment or f"listed in {path.name}",
        expires=expires,
        source=path.name,
    )
