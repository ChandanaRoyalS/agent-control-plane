"""Who answered, and the two things the old row could not say.

`build_decide` wrote the subject, the tool, the rule and the operator's reason
into the chain — and nothing identifying the operator, while its own docstring
said the row an investigation wants is "who approved the delete".
"""

from __future__ import annotations

import pytest

from acp.approvals.operators import (
    MIN_TOKEN_LENGTH,
    SHARED_OPERATOR,
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


def test_a_shared_token_records_as_shared_rather_than_as_a_name() -> None:
    """Neither empty nor plausible.

    Empty reads as "this field is not populated yet"; a name would be a lie. A
    row saying `shared` states exactly what is known — somebody holding the
    shared credential approved this, and the record cannot say who.
    """
    directory = directory_from_settings("a-shared-token-long-enough-to-pass")

    assert directory is not None
    assert directory.names == (SHARED_OPERATOR,)


def test_named_operators_win_over_a_shared_token() -> None:
    """Between the two, the safe guess is the one that records more."""
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
