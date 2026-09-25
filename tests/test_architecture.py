"""Enforce the ports-and-adapters dependency rule by inspecting imports statically."""

import ast
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

PACKAGE_ROOT = Path(__file__).parents[1] / "src" / "vulnrank"

# Standard-library modules that do IO; the pure core must not reach for them.
IO_STDLIB = frozenset(
    {"http", "io", "os", "pathlib", "shutil", "socket", "subprocess", "tempfile", "urllib"}
)

ALLOWED_THIRD_PARTY = frozenset({"pydantic"})


def _module_name(path: Path) -> str:
    parts = path.relative_to(PACKAGE_ROOT.parent).with_suffix("").parts
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def _imports(path: Path) -> Iterator[str]:
    module = _module_name(path)
    package = module if path.name == "__init__.py" else module.rpartition(".")[0]
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                yield node.module or ""
            else:
                base = package.rsplit(".", node.level - 1)[0] if node.level > 1 else package
                yield f"{base}.{node.module}" if node.module else base


def _violations(layer: str, allowed_internal: tuple[str, ...]) -> list[str]:
    problems: list[str] = []
    for path in sorted((PACKAGE_ROOT / layer).rglob("*.py")):
        for name in _imports(path):
            top = name.split(".")[0]
            if top == "vulnrank":
                ok = any(name == p or name.startswith(f"{p}.") for p in allowed_internal)
            elif top in sys.stdlib_module_names:
                ok = top not in IO_STDLIB
            else:
                ok = top in ALLOWED_THIRD_PARTY
            if not ok:
                problems.append(f"{path.relative_to(PACKAGE_ROOT)} imports {name}")
    return problems


@pytest.mark.parametrize(
    ("layer", "allowed_internal"),
    [
        ("domain", ("vulnrank.domain",)),
        ("ports", ("vulnrank.domain", "vulnrank.ports")),
        ("application", ("vulnrank.domain", "vulnrank.ports", "vulnrank.application")),
    ],
)
def test_layer_only_depends_on_inner_layers(layer: str, allowed_internal: tuple[str, ...]) -> None:
    assert _violations(layer, allowed_internal) == []


def test_the_rule_catches_a_violation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_root = tmp_path / "vulnrank"
    (fake_root / "domain").mkdir(parents=True)
    (fake_root / "domain" / "bad.py").write_text(
        "import httpx\nfrom pathlib import Path\nfrom ..adapters import inputs\n"
        "from . import models\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys.modules[__name__], "PACKAGE_ROOT", fake_root)
    assert _violations("domain", ("vulnrank.domain",)) == [
        "domain/bad.py imports httpx",
        "domain/bad.py imports pathlib",
        "domain/bad.py imports vulnrank.adapters",
    ]
