"""The public surface this project's version number is a promise about.

Four sections: every ``ACP_*`` variable with type and default, every CLI command and
option, the audit record's shape, and this module's own stamp. The Python API and the
wire protocol (ADR 0001) are excluded. Pure: no files, no servers, parser passed in,
so ``tests/unit/test_surface.py`` can test by mutating dictionaries.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, fields
from enum import Enum
from pathlib import Path
from types import UnionType
from typing import Any, Final, Union, get_args, get_origin

from pydantic_settings import BaseSettings

from acp.audit.record import AUDIT_VERSION, AuditRecord, Category, Outcome
from acp.config import GatewaySettings

SURFACE_VERSION: Final = "acp-surface-v1"
"""Stamped into the snapshot; independent of the audit and other version stamps."""

MISSING: Final = "(absent)"
"""Printed for a name present on only one side (distinct from a blank value)."""

HELP_OPTIONS: Final = frozenset({"-h", "--help"})
"""Options argparse adds to every parser; not recorded."""


@dataclass(frozen=True, slots=True)
class Setting:
    """One environment variable a deployment can set."""

    variable: str
    type: str
    default: str


@dataclass(frozen=True, slots=True)
class Command:
    """One command path as typed (``acp audit verify``), and the options it accepts."""

    path: str
    options: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Difference:
    """One way the current surface departs from the captured one."""

    section: str
    name: str
    was: str
    now: str


# ---------------------------------------------------------------------------
# Rendering values and types as strings, so snapshots compare textually and stably.
# ---------------------------------------------------------------------------


def render_value(value: object) -> str:
    """A default, as a string a reviewer can read."""
    if value is None:
        return "None"
    if isinstance(value, Enum):
        return str(value.value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, str):
        return repr(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(render_value(item) for item in value) + "]"
    return str(value)


def render_type(annotation: object) -> str:
    """A type as a string, spelling out enum members so a new member shows as a change."""
    if annotation is None or annotation is type(None):
        return "None"

    origin = get_origin(annotation)
    if origin is not None:
        arguments = get_args(annotation)
        if origin is UnionType or origin is Union:
            return " | ".join(render_type(item) for item in arguments)
        inner = ", ".join(render_type(item) for item in arguments)
        return f"{render_type(origin)}[{inner}]"

    if isinstance(annotation, type) and issubclass(annotation, Enum):
        members = "|".join(str(member.value) for member in annotation)
        return f"{annotation.__name__}({members})"

    name = getattr(annotation, "__name__", None)
    return name if isinstance(name, str) else str(annotation)


# ---------------------------------------------------------------------------
# The four sections
# ---------------------------------------------------------------------------


def settings(model: type[BaseSettings] = GatewaySettings) -> tuple[Setting, ...]:
    """Every environment variable the gateway reads, with its default.

    Defaults come from `model_construct()`, which calls default factories and does not
    read the environment, so the local machine's settings never leak into a snapshot.
    """
    prefix = model.model_config.get("env_prefix") or ""
    defaults = model.model_construct()

    return tuple(
        sorted(
            (
                Setting(
                    variable=f"{prefix}{name}".upper(),
                    type=render_type(field.annotation),
                    default=render_value(getattr(defaults, name, None)),
                )
                for name, field in model.model_fields.items()
            ),
            key=lambda setting: setting.variable,
        )
    )


def aliases(model: type[BaseSettings] = GatewaySettings) -> tuple[str, ...]:
    """Field names carrying an alias.

    `settings()` assumes none do (variable = prefix + upper-cased name); a test
    asserts this is empty.
    """
    return tuple(
        name
        for name, field in model.model_fields.items()
        if field.validation_alias is not None or field.alias is not None
    )


def audit() -> dict[str, list[str]]:
    """The audit record's shape; fields in declaration order so a reordering shows."""
    return {
        "version": [AUDIT_VERSION],
        "categories": sorted(member.value for member in Category),
        "outcomes": sorted(member.value for member in Outcome),
        "fields": [field.name for field in fields(AuditRecord)],
    }


def commands(parser: argparse.ArgumentParser, path: str = "acp") -> tuple[Command, ...]:
    """Every command path under `parser`, and the options each accepts.

    Walks the parser object, not the source, so verbs built in loops are found.
    The private `_actions` is read via `getattr`; if it vanishes the result is empty,
    which the snapshot test catches.
    """
    actions: Sequence[argparse.Action] = getattr(parser, "_actions", ())

    found = [
        Command(
            path=path,
            options=tuple(
                sorted(
                    option
                    for action in actions
                    for option in action.option_strings
                    if option not in HELP_OPTIONS
                )
            ),
        )
    ]

    for action in actions:
        choices = action.choices
        if not isinstance(choices, dict):
            continue
        for name, child in choices.items():
            if isinstance(child, argparse.ArgumentParser):
                found.extend(commands(child, f"{path} {name}"))

    return tuple(sorted(found, key=lambda command: command.path))


def describe(parser: argparse.ArgumentParser) -> dict[str, Any]:
    """The whole surface, in the shape the snapshot file holds."""
    return {
        "surface_version": SURFACE_VERSION,
        "settings": [
            {"variable": s.variable, "type": s.type, "default": s.default} for s in settings()
        ],
        "commands": [{"path": c.path, "options": list(c.options)} for c in commands(parser)],
        "audit": audit(),
    }


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


def _row_key(row: Mapping[str, Any], key: str) -> str:
    return str(row.get(key, ""))


def _row_text(row: Mapping[str, Any], key: str) -> str:
    rest = {name: value for name, value in row.items() if name != key}
    return json.dumps(rest, sort_keys=True)


def _index(surface: Mapping[str, Any], section: str, key: str) -> dict[str, str]:
    rows = surface.get(section)
    if not isinstance(rows, list):
        return {}
    return {_row_key(row, key): _row_text(row, key) for row in rows if isinstance(row, Mapping)}


def _index_audit(surface: Mapping[str, Any]) -> dict[str, str]:
    block = surface.get("audit")
    if not isinstance(block, Mapping):
        return {}
    return {str(name): json.dumps(value) for name, value in block.items()}


def _differences(
    section: str, was: Mapping[str, str], now: Mapping[str, str]
) -> Iterator[Difference]:
    for name in sorted(set(was) | set(now)):
        before = was.get(name, MISSING)
        after = now.get(name, MISSING)
        if before != after:
            yield Difference(section=section, name=name, was=before, now=after)


def compare(captured: Mapping[str, Any], current: Mapping[str, Any]) -> tuple[Difference, ...]:
    """Every way `current` departs from `captured`; empty means unchanged."""
    found: list[Difference] = []

    stamped = str(captured.get("surface_version", MISSING))
    running = str(current.get("surface_version", MISSING))
    if stamped != running:
        found.append(
            Difference(section="surface_version", name="surface_version", was=stamped, now=running)
        )

    found.extend(
        _differences(
            "settings",
            _index(captured, "settings", "variable"),
            _index(current, "settings", "variable"),
        )
    )
    found.extend(
        _differences(
            "commands",
            _index(captured, "commands", "path"),
            _index(current, "commands", "path"),
        )
    )
    found.extend(_differences("audit", _index_audit(captured), _index_audit(current)))

    return tuple(found)


def render(differences: Sequence[Difference]) -> str:
    """The differences, as lines a person reads in a failing build."""
    if not differences:
        return "The public surface is unchanged."

    lines = [f"The public surface changed in {len(differences)} place(s):", ""]
    for difference in differences:
        lines.append(f"  [{difference.section}] {difference.name}")
        lines.append(f"      was: {difference.was}")
        lines.append(f"      now: {difference.now}")
    return "\n".join(lines)
