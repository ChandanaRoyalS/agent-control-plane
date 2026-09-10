"""Who answered, and the two things the old row could not say.

`build_decide` wrote the subject, the tool, the rule and the operator's reason
into the chain — and nothing identifying the operator, while its own docstring
said the row an investigation wants is "who approved the delete".
"""

from __future__ import annotations

import pytest

from acp.approvals.operators import (
    MIN_TOKEN_LENGTH,
    Operator,
    OperatorDirectory,
    directory_from_settings,
    load_operators,
)
from acp.exceptions import ConfigurationError

ALICE = "alice-token-long-enough-to-be-accepted"
BOB = "bob-token-also-long-enough-to-be-accepted"


def test_a_credential_resolves_to_the_person_who_holds_it() -> None:
    directory = OperatorDirectory([Operator("alice", ALICE), Operator("bob", BOB)])

    resolved = directory.resolve(BOB)

    assert resolved is not None
    assert resolved.name == "bob"


def test_an_unknown_credential_resolves_to_nobody() -> None:
    directory = OperatorDirectory([Operator("alice", ALICE)])

    assert directory.resolve(BOB) is None
    assert directory.resolve("") is None


def test_a_shared_token_is_refused_rather_than_downgraded() -> None:
    """**The judgment this reverses.**

    An earlier version accepted a shared credential and recorded every approval
    as `shared`, with a warning, so that an existing deployment would not fail
    to start over the *quality* of its evidence.

    ADR 0061 — written three commits earlier, about the same shape of problem —
    says the opposite: isolation that has to be opted into is isolation the
    shipped configuration does not have. A warning at startup is a line in a log
    a container platform discards; the deployment then runs for a year, and the
    day somebody asks who approved the delete the answer is the set of people
    holding one secret.
    """
    with pytest.raises(ConfigurationError, match="ACP_APPROVAL_OPERATORS_FILE"):
        directory_from_settings("a-shared-token-long-enough-to-pass")


def test_the_refusal_says_how_to_fix_it() -> None:
    """A startup failure a deployer cannot act on is an outage with extra
    steps. This one carries the file format in the message."""
    with pytest.raises(ConfigurationError) as raised:
        directory_from_settings("a-shared-token-long-enough-to-pass")

    message = str(raised.value)
    assert "operators:" in message
    assert "name: alice" in message
    assert "ADR 0062" in message


def test_named_operators_are_accepted_alongside_a_stale_shared_token() -> None:
    """The migration path: a deployment that sets the file may still have the
    old variable in its environment, and should start rather than be told off
    for a setting it has already superseded."""
    directory = directory_from_settings("a-shared-token-long-enough-to-pass", {"alice": ALICE})

    assert directory is not None
    assert directory.names == ("alice",)


def test_no_credential_at_all_means_no_channel() -> None:
    """`None` rather than an empty directory: an approval channel with no
    operators is not a channel that refuses, it is one that should not be
    routed at all."""
    assert directory_from_settings("") is None


def test_a_short_credential_is_refused() -> None:
    """It opens a channel showing every argument of every held call.

    `dev-only-operator-token` is 23 characters, and it was the compose default.
    """
    with pytest.raises(ConfigurationError, match="minimum"):
        OperatorDirectory([Operator("alice", "short")])

    assert len("dev-only-operator-token") < MIN_TOKEN_LENGTH


def test_two_operators_may_not_share_a_name() -> None:
    with pytest.raises(ConfigurationError, match="name"):
        OperatorDirectory([Operator("alice", ALICE), Operator("alice", BOB)])


def test_two_operators_may_not_share_a_credential() -> None:
    """The row would name whichever was listed first, which is a name chosen by
    configuration order rather than by who authenticated."""
    with pytest.raises(ConfigurationError, match="credential"):
        OperatorDirectory([Operator("alice", ALICE), Operator("bob", ALICE)])


def test_an_operator_name_is_validated_at_load_time(tmp_path: object) -> None:
    """It is written verbatim into an audit record, so it is constrained once
    here rather than escaped everywhere it is read."""
    from pathlib import Path  # noqa: PLC0415

    assert isinstance(tmp_path, Path)
    path = tmp_path / "operators.yaml"
    path.write_text(f'operators:\n  - name: "../etc"\n    token: {ALICE}\n', encoding="utf-8")

    with pytest.raises(ConfigurationError, match="lowercase slug"):
        load_operators(path)


def test_a_file_without_an_operators_list_is_refused(tmp_path: object) -> None:
    from pathlib import Path  # noqa: PLC0415

    assert isinstance(tmp_path, Path)
    path = tmp_path / "operators.yaml"
    path.write_text("nothing: here\n", encoding="utf-8")

    with pytest.raises(ConfigurationError, match="operators"):
        load_operators(path)
