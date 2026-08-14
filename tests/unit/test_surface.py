"""The public surface, and proof that its snapshot check can fail.

`acp.surface` is pure, so every one of these runs without a container, a
network or the MCP SDK. The snapshot check against the *real* parser lives in
`test_surface_snapshot.py`, which needs `acp.cli` and therefore the SDK.

The mutation tests are the point of the file. A snapshot test that has never
been seen to fail is a claim about whoever wrote it (ADR 0023), and this one
guards the thing nobody notices going wrong: a renamed environment variable
that leaves the gateway starting with the old default and saying nothing.
"""

from __future__ import annotations

import argparse
import copy
from enum import StrEnum
from pathlib import Path
from typing import Any

import pytest
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from acp.audit.record import AUDIT_VERSION, Category, Outcome
from acp.surface import (
    MISSING,
    SURFACE_VERSION,
    Command,
    aliases,
    audit,
    commands,
    compare,
    describe,
    render,
    render_type,
    render_value,
    settings,
)


class Colour(StrEnum):
    RED = "red"
    BLUE = "blue"


def _parser() -> argparse.ArgumentParser:
    """A parser shaped like the real one, including a loop-built group.

    `acp audit` and `acp secrets` build their verbs in a `for` loop. A reading
    of the source that looked for `add_parser("literal")` would find every
    other command and miss those, and report the shortfall as a complete
    answer. This fixture exists so that failure mode is covered by a test
    rather than by a comment.
    """
    parser = argparse.ArgumentParser(prog="acp")
    parser.add_argument("--version", action="version", version="test")

    subparsers = parser.add_subparsers(dest="command")

    probe = subparsers.add_parser("probe")
    probe.add_argument("--url")

    audit_group = subparsers.add_parser("audit")
    verbs = audit_group.add_subparsers(dest="audit_command")
    for verb in ("verify", "checkpoint"):
        built = verbs.add_parser(verb)
        built.add_argument("--log-file")

    return parser


def _surface() -> dict[str, Any]:
    return describe(_parser())


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "None"),
        (True, "True"),
        (9090, "9090"),
        (86400.0, "86400.0"),
        ("INFO", "'INFO'"),
        (Path("config/policy.yaml"), "config/policy.yaml"),
        ([], "[]"),
        (["127.0.0.1", "localhost"], "['127.0.0.1', 'localhost']"),
        (Colour.RED, "red"),
    ],
)
def test_a_default_renders_to_something_a_reviewer_can_read(value: object, expected: str) -> None:
    assert render_value(value) == expected


def test_a_string_default_is_quoted() -> None:
    """So that an empty string is visible as `''` rather than as nothing at all.

    `ACP_APPROVAL_OPERATOR_TOKEN` defaults to the empty string, and its default
    changing to a value would be the most alarming line this snapshot could
    ever carry.
    """
    assert render_value("") == "''"


def test_an_enum_type_spells_out_its_members() -> None:
    """A fourth firewall mode is an addition to the surface, and a snapshot
    recording only the word `Mode` would not show it."""
    assert render_type(Colour) == "Colour(red|blue)"


def test_an_optional_type_renders_as_a_union() -> None:
    assert render_type(Path | None) == "Path | None"


def test_a_generic_type_renders_its_arguments() -> None:
    assert render_type(list[str]) == "list[str]"


# ---------------------------------------------------------------------------
# The sections
# ---------------------------------------------------------------------------


def test_every_setting_is_prefixed_and_upper_case() -> None:
    found = settings()
    assert found, "no settings were found at all"
    for setting in found:
        assert setting.variable.startswith("ACP_")
        assert setting.variable == setting.variable.upper()


def test_the_settings_are_sorted() -> None:
    """A snapshot whose order depends on declaration order produces a diff
    every time somebody moves a field, and a reviewer learns to skip it."""
    found = [setting.variable for setting in settings()]
    assert found == sorted(found)


def test_no_setting_declares_an_alias() -> None:
    """THE ASSUMPTION `settings()` RESTS ON.

    Variable names are computed as prefix + field name upper-cased, which is
    what pydantic-settings does unless a field declares an alias. The day
    somebody adds one, this fails and names the field — rather than the
    snapshot silently recording a variable the gateway does not read.
    """
    assert aliases() == ()


def test_a_setting_reads_its_default_without_reading_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A snapshot captured on a configured machine would record that machine's
    configuration as this project's defaults."""
    monkeypatch.setenv("ACP_PORT", "31337")
    ports = [s.default for s in settings() if s.variable == "ACP_PORT"]
    assert ports == ["8080"]


def test_a_default_factory_is_called_rather_than_described() -> None:
    class Model(BaseSettings):
        model_config = SettingsConfigDict(env_prefix="ACP_")
        hosts: list[str] = Field(default_factory=lambda: ["a", "b"])

    assert settings(Model)[0].default == "['a', 'b']"


def test_the_audit_section_carries_the_chain_stamp_and_every_field() -> None:
    block = audit()
    assert block["version"] == [AUDIT_VERSION]
    assert set(block["categories"]) == {member.value for member in Category}
    assert set(block["outcomes"]) == {member.value for member in Outcome}
    assert "tenant" in block["fields"]


def test_commands_walks_into_verbs_built_in_a_loop() -> None:
    """The failure an AST reading of the source would have."""
    paths = [command.path for command in commands(_parser())]
    assert "acp audit verify" in paths
    assert "acp audit checkpoint" in paths


def test_a_commands_path_is_what_a_person_types() -> None:
    paths = [command.path for command in commands(_parser())]
    assert paths[0] == "acp"
    assert "acp probe" in paths


def test_help_is_not_recorded_as_an_option() -> None:
    for command in commands(_parser()):
        assert "-h" not in command.options
        assert "--help" not in command.options


def test_options_are_recorded() -> None:
    found = {command.path: command.options for command in commands(_parser())}
    assert found["acp probe"] == ("--url",)
    assert found["acp"] == ("--version",)


def test_a_parser_without_actions_still_yields_its_own_path() -> None:
    """`getattr(parser, '_actions', ())` degrades rather than raising, and the
    degradation must not silently produce an empty surface."""
    assert commands(argparse.ArgumentParser(prog="acp")) == (Command(path="acp", options=()),)


def test_the_surface_is_stamped() -> None:
    assert _surface()["surface_version"] == SURFACE_VERSION


# ---------------------------------------------------------------------------
# Comparison — and the mutations that prove it can fail
# ---------------------------------------------------------------------------


def test_an_unchanged_surface_reports_nothing() -> None:
    surface = _surface()
    assert compare(surface, copy.deepcopy(surface)) == ()
    assert "unchanged" in render(())


def test_a_removed_setting_is_caught() -> None:
    captured = _surface()
    current = copy.deepcopy(captured)
    gone = current["settings"].pop(0)

    found = compare(captured, current)
    assert [d.name for d in found] == [gone["variable"]]
    assert found[0].now == MISSING


def test_an_added_setting_is_caught() -> None:
    captured = _surface()
    current = copy.deepcopy(captured)
    current["settings"].append({"variable": "ACP_BRAND_NEW", "type": "bool", "default": "False"})

    found = compare(captured, current)
    assert [d.name for d in found] == ["ACP_BRAND_NEW"]
    assert found[0].was == MISSING


def test_a_changed_default_is_caught() -> None:
    """THE ONE THAT MATTERS MOST.

    A renamed variable at least fails loudly somewhere eventually. A default
    that quietly moves from `True` to `False` is a security control switching
    itself off with no error, no warning and a passing test suite — this
    project's most repeated bug (lesson 46).
    """
    captured = _surface()
    current = copy.deepcopy(captured)
    for setting in current["settings"]:
        if setting["variable"] == "ACP_AUDIT_FSYNC":
            setting["default"] = "False"

    found = compare(captured, current)
    assert [d.name for d in found] == ["ACP_AUDIT_FSYNC"]
    assert "True" in found[0].was
    assert "False" in found[0].now


def test_a_renamed_command_is_caught_as_two_differences() -> None:
    """A rename is a removal and an addition, and reporting it as one would
    require guessing which new name replaced which old one."""
    captured = _surface()
    current = copy.deepcopy(captured)
    for command in current["commands"]:
        if command["path"] == "acp audit verify":
            command["path"] = "acp audit check"

    found = compare(captured, current)
    assert {d.name for d in found} == {"acp audit verify", "acp audit check"}


def test_a_removed_option_is_caught() -> None:
    captured = _surface()
    current = copy.deepcopy(captured)
    for command in current["commands"]:
        if command["path"] == "acp probe":
            command["options"] = []

    found = compare(captured, current)
    assert [d.name for d in found] == ["acp probe"]


def test_a_changed_audit_record_is_caught() -> None:
    """A chain written by one release has to still verify under the next."""
    captured = _surface()
    current = copy.deepcopy(captured)
    current["audit"]["fields"].remove("tenant")

    found = compare(captured, current)
    assert [d.section for d in found] == ["audit"]
    assert [d.name for d in found] == ["fields"]


def test_a_changed_surface_stamp_is_caught_on_its_own() -> None:
    captured = _surface()
    current = copy.deepcopy(captured)
    current["surface_version"] = "acp-surface-v2"

    found = compare(captured, current)
    assert [d.section for d in found] == ["surface_version"]


def test_a_snapshot_missing_a_whole_section_does_not_report_nothing() -> None:
    """LESSON 65. A comparison against an empty or truncated snapshot must not
    look like agreement — which is exactly what a naive `get(section, [])` on
    both sides would produce if the *current* side were also empty."""
    captured = _surface()
    found = compare({"surface_version": SURFACE_VERSION}, captured)
    assert found, "an empty snapshot compared clean against a real surface"


def test_the_rendering_names_the_section_and_both_values() -> None:
    captured = _surface()
    current = copy.deepcopy(captured)
    current["settings"][0]["default"] = "something else"

    text = render(compare(captured, current))
    assert "settings" in text
    assert "was:" in text
    assert "now:" in text
