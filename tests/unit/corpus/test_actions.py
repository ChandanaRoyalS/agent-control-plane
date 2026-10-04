"""The policy engine against the actions injections are after.

Three things are pinned: the read/write rule fails toward a person (an unknown
verb is held, not allowed); a chain is only as permitted as its least permitted
step; and the committed actions file agrees with the catalogue it names, so a
tool cannot be scored against a policy that has never heard of it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acp.corpus.actions import (
    Actions,
    Outcome,
    evaluate_actions,
    is_read,
    least_privilege,
    load_actions,
    outcome,
    reads_allowed_writes_held,
)
from acp.corpus.external import load_external_split
from acp.exceptions import ConfigurationError

CATALOGUE = ("gmail__SendEmail", "gmail__ReadEmail", "amazon__ViewSavedAddresses", "lock__Unbar")


@pytest.mark.parametrize(
    ("tool", "read"),
    [
        ("gmail__ReadEmail", True),
        ("amazon__ViewSavedAddresses", True),
        ("gmail__SendEmail", False),
        ("lock__Unbar", False),
        ("weird", False),
    ],
)
def test_reads_are_named_by_verb_and_anything_else_is_a_write(tool: str, read: bool) -> None:
    assert is_read(tool) is read


def test_a_chain_is_as_permitted_as_its_least_permitted_step() -> None:
    gated = reads_allowed_writes_held(CATALOGUE)
    assert outcome(gated, ["amazon__ViewSavedAddresses"]) is Outcome.EXECUTES
    assert outcome(gated, ["amazon__ViewSavedAddresses", "gmail__SendEmail"]) is Outcome.HELD
    narrow = least_privilege(["gmail__ReadEmail"])
    assert outcome(narrow, ["gmail__ReadEmail"]) is Outcome.EXECUTES
    assert outcome(narrow, ["amazon__ViewSavedAddresses", "gmail__SendEmail"]) is Outcome.BLOCKED


def test_the_report_names_what_executes_and_what_it_costs() -> None:
    actions = Actions(
        catalogue=CATALOGUE,
        user_tools=("gmail__ReadEmail",),
        attacker_tools={
            "ds/a": ("amazon__ViewSavedAddresses", "gmail__SendEmail"),
            "dh/b": ("gmail__ReadEmail",),
        },
    )
    report = evaluate_actions(actions, ["ds/a", "dh/b"])
    rows = {(r.policy, r.subset): r for r in report.rows}

    assert rows[("least privilege", "dh")].executing == ("dh/b",)
    assert rows[("least privilege", "ds")].outcomes[Outcome.BLOCKED] == 1
    assert rows[("reads allowed, writes held", "ds")].outcomes[Outcome.HELD] == 1
    assert all(b.allowed == 1 for b in report.burden)
    assert (report.read_tools, report.write_tools) == (2, 2)


def test_an_unknown_group_is_an_error() -> None:
    actions = Actions(catalogue=CATALOGUE, user_tools=(), attacker_tools={})
    with pytest.raises(ConfigurationError, match="no attacker tool chain"):
        evaluate_actions(actions, ["ds/zzz"])


@pytest.mark.parametrize(
    ("body", "match"),
    [
        ("{nope", "cannot read"),
        ("{}", "needs catalogue"),
        (
            json.dumps({"catalogue": ["a__B"], "user_tools": ["x__Y"], "attacker_tools": {}}),
            "not in the catalogue",
        ),
    ],
)
def test_a_malformed_actions_file_stops_the_load(tmp_path: Path, body: str, match: str) -> None:
    (tmp_path / "actions.json").write_text(body, encoding="utf-8")
    with pytest.raises(ConfigurationError, match=match):
        load_actions(tmp_path)


def test_every_committed_group_has_a_chain() -> None:
    split = load_external_split()
    actions = load_actions()
    groups = {d.group for d in (*split.development, *split.heldout)}
    assert groups == set(actions.attacker_tools)
