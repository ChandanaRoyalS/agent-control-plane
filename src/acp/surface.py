"""The public surface this project's version number is a promise about.

Task 67. Semantic versioning is a contract, and a contract needs a subject.
"Breaking change" is undefined until somebody says **breaking for whom** — and
for a gateway the answer is almost never the Python API. Nobody imports
``acp``; they run the container.

So the surface is the four things a deployment can actually depend on:

- **every ``ACP_*`` environment variable**, its type and its default, because a
  renamed variable is a gateway that starts with the old behaviour and says
  nothing (lesson 46, and this project has hit it six times)
- **every CLI command and option**, because they are in somebody's Makefile
- **the audit record's shape** — its version stamp, categories, outcomes and
  fields — because a chain written by 1.0 has to still verify under 1.1
- **this module's own version stamp**, so what "the surface" means can change
  without an old snapshot being reinterpreted under the new rule

What is deliberately **not** here: the Python API, the policy file's semantics
beyond its schema, the wire protocol (pinned by ADR 0001 to one specification
revision and checked by the conformance suite, which is a stronger guarantee
than a snapshot), and anything under ``perf/`` or ``scripts/``.

**Everything in this module is pure.** It reads declarations and returns data;
it opens no file, imports nothing that constructs a server, and takes the
argument parser as a parameter rather than building one. That is what lets the
comparison be tested by mutating a dictionary rather than by editing the
project and running it — see ``tests/unit/test_surface.py``, where the snapshot
check is broken on purpose three ways.
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
"""Stamped into the snapshot.

A third stamp rather than a shared one, for the same reason the audit chain,
the approval fingerprint and the result-cache key each carry their own: a
change made for one carries no implication for the others.
"""

MISSING: Final = "(absent)"
"""What a comparison prints for a name present on only one side.

A word rather than an empty string, because an empty string in a diff column
reads as "the value is blank" and this means "there is no such thing here".
"""

HELP_OPTIONS: Final = frozenset({"-h", "--help"})
"""Excluded from the recorded options.

`argparse` adds these to every parser it creates. Recording them would put the
same two strings on every command in the snapshot and say nothing about a
decision this project made.
"""


@dataclass(frozen=True, slots=True)
class Setting:
    """One environment variable a deployment can set."""

    variable: str
    type: str
    default: str


@dataclass(frozen=True, slots=True)
class Command:
    """One command path, and the options it accepts.

    `path` is the words a person types — ``acp audit verify`` — rather than the
    parser's internal name, because the words are what is in somebody's script.
    """

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
# Rendering values and types stably
#
# Everything below returns a string rather than a JSON value. A snapshot is
# compared textually and read by a person in a pull request diff; `"3600.0"`
# and `3600.0` are the same fact, and only one of them survives a round trip
# through JSON on every Python version without argument.
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
    """A type, as a string, with an enum's members spelled out.

    The members matter: `ACP_FIREWALL_MODE` accepting a fourth mode is an
    addition to the surface, and a snapshot recording only the word `Mode`
    would not show it.
    """
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

    Defaults come from `model_construct()` rather than from each field's
    declaration, so a `default_factory` is *called* and a list default appears
    as the list it produces. Reading the declaration would print the factory's
    repr, which changes with the interpreter and tells a reviewer nothing.

    `model_construct` does not read the environment, which is the property that
    matters here: a snapshot captured on a machine with `ACP_AUDIT_FSYNC` set
    would record that machine's configuration as this project's default.
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
    """Field names carrying a validation alias.

    `settings()` computes each variable as prefix + field name upper-cased,
    which is what pydantic-settings does **unless** a field declares an alias.
    None do. This exists so that the assumption is asserted rather than
    believed: the day somebody adds an alias, the test that calls this fails and
    names the field, instead of the snapshot silently recording a variable the
    gateway does not read.
    """
    return tuple(
        name
        for name, field in model.model_fields.items()
        if field.validation_alias is not None or field.alias is not None
    )


def audit() -> dict[str, list[str]]:
    """The audit record's shape.

    Fields in declaration order rather than sorted: a reordering is a change to
    the record and should be visible as one.
    """
    return {
        "version": [AUDIT_VERSION],
        "categories": sorted(member.value for member in Category),
        "outcomes": sorted(member.value for member in Outcome),
        "fields": [field.name for field in fields(AuditRecord)],
    }


def commands(parser: argparse.ArgumentParser, path: str = "acp") -> tuple[Command, ...]:
    """Every command path under `parser`, and the options each accepts.

    Walks the parser **object**, not the source. Two of this CLI's command
    groups build their verbs in a `for` loop, so an AST reading of
    `add_parser("...")` would find the ones written out as literals, miss the
    ones built in loops, and report a confident, incomplete answer. Lesson 53's
    shape: a completeness search that silently truncates.

    `_actions` is private and there is no public equivalent. Reached through
    `getattr` so that a future argparse without it degrades to an empty list
    rather than an exception at capture time -- and the emptiness is caught,
    because the snapshot test asserts the surface is not empty before it asserts
    anything about its contents (lesson 65).
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
    """Every way `current` departs from `captured`.

    Empty means the surface is unchanged, which is the only state that needs no
    decision about the version number.
    """
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
