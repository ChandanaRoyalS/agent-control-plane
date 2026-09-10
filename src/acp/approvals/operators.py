"""Which person answered, not merely that somebody with the credential did.

`build_decide` recorded an approval into the hash chain with the subject, the
tool, the rule and the operator's free-text reason — and nothing identifying the
operator. Its own docstring said the row an investigation wants is *"who
approved the delete, and what did they say they had checked"*, and the row could
answer the second half only.

That is not a small omission for an audit product. An approval is the one record
in this system describing a thing a **person** did; every other row describes a
decision the gateway made. A chain that can show a call being held and then
running, with a reason in between and no name attached, has recorded that
somebody with the credential said yes. If four people hold that credential, the
record narrows an incident to four people, and the reason field is the only
thing distinguishing them — a free-text field, written by whoever is explaining
themselves.

So the credential identifies a **named operator**, and the name goes in the
chain. A deployment with one shared token still works and still records — as
`shared`, with a warning at startup, because pretending a shared secret names
somebody would be worse than admitting it does not.
"""

from __future__ import annotations

import logging
import re
import secrets
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import yaml

from acp.exceptions import ConfigurationError

logger = logging.getLogger(__name__)

OPERATOR_NAME: Final = re.compile(r"^[a-z0-9]+([-_][a-z0-9]+)*$")
"""What an operator may be called.

The same shape as a rule name and a tenant label, and for the same reason: it is
written verbatim into an audit record, so it is validated once here rather than
escaped everywhere it is read.
"""

SHARED_OPERATOR: Final = "shared"
"""The name recorded when the deployment configured one anonymous token.

Deliberately not a person's name and deliberately not empty. Empty would read as
"this field is not populated yet"; a plausible-looking name would be a lie. A
row saying `shared` states exactly what is known: somebody holding the shared
credential approved this, and the record cannot say who.
"""

MIN_TOKEN_LENGTH: Final = 32
"""Shortest operator credential accepted.

The channel it opens shows every argument of every held call — patient records,
salary figures, whatever the tools reach — and grants the power to approve them.
`dev-only-operator-token` is 23 characters; a credential guarding that should
not be guessable by somebody who has seen the compose file.
"""


@dataclass(frozen=True, slots=True)
class Operator:
    """A person entitled to answer a held call."""

    name: str
    token: str


class OperatorDirectory:
    """The operators this deployment recognises, resolved in constant time."""

    def __init__(self, operators: Iterable[Operator]) -> None:
        self._operators = tuple(operators)
        names = [operator.name for operator in self._operators]
        if len(set(names)) != len(names):
            msg = "two operators share a name; the audit row would not say which one approved"
            raise ConfigurationError(msg)
        tokens = [operator.token for operator in self._operators]
        if len(set(tokens)) != len(tokens):
            msg = (
                "two operators share a credential; the audit row would name "
                "whichever was listed first"
            )
            raise ConfigurationError(msg)
        for operator in self._operators:
            if len(operator.token) < MIN_TOKEN_LENGTH:
                msg = (
                    f"operator {operator.name!r}: credential is "
                    f"{len(operator.token)} characters, minimum {MIN_TOKEN_LENGTH}. "
                    f"It opens a channel showing every argument of every held call."
                )
                raise ConfigurationError(msg)

    def __len__(self) -> int:
        return len(self._operators)

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(operator.name for operator in self._operators)

    def resolve(self, presented: str) -> Operator | None:
        """Who presented this credential, or ``None``.

        Every candidate is compared, and the loop does not stop at the first
        hit. `compare_digest` makes each comparison constant time; returning
        early would leak the matching operator's *position* in the directory
        through the response time, which is a small leak and free to not have.
        """
        found: Operator | None = None
        for operator in self._operators:
            if secrets.compare_digest(presented, operator.token):
                found = operator
        return found


def directory_from_settings(
    single_token: str, named: Mapping[str, str] | None = None
) -> OperatorDirectory | None:
    """The directory this configuration asks for, or ``None`` for no channel.

    ``None`` rather than an empty directory, because an approval channel with no
    operators is not a channel that refuses — it is a channel that should not be
    routed at all (task 55). Presence-based, like every other switch in
    `runtime`.

    Named operators win when both are configured, because the alternative is
    guessing which the operator meant and the safe guess is the one that
    records less.
    """
    if named:
        return OperatorDirectory(Operator(name=name, token=token) for name, token in named.items())
    if single_token:
        logger.warning(
            "approvals.shared_credential",
            extra={
                "consequence": (
                    "approvals will be recorded as 'shared'; the chain cannot say "
                    "which person approved a call"
                ),
                "remedy": "configure ACP_APPROVAL_OPERATORS_FILE with one credential per person",
            },
        )
        return OperatorDirectory([Operator(name=SHARED_OPERATOR, token=single_token)])
    return None


def load_operators(path: Path) -> dict[str, str]:
    """Read the operators file, or raise ``ConfigurationError``.

    Shaped like the issuers file and validated like it: the failure a deployer
    sees at 3am should name the file and the entry, not carry a library's
    account of a dictionary.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"cannot read operators file {str(path)!r}: {exc}"
        raise ConfigurationError(msg) from exc
    try:
        document = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        msg = f"operators file {str(path)!r} is not valid YAML: {exc}"
        raise ConfigurationError(msg) from exc
    if not isinstance(document, dict) or not isinstance(document.get("operators"), list):
        msg = f"operators file {str(path)!r} must be a mapping with an `operators` list"
        raise ConfigurationError(msg)

    named: dict[str, str] = {}
    for index, entry in enumerate(document["operators"]):
        if not isinstance(entry, dict):
            msg = f"operators file {str(path)!r}: entry #{index} is not a mapping"
            raise ConfigurationError(msg)
        name, token = entry.get("name"), entry.get("token")
        if not isinstance(name, str) or not OPERATOR_NAME.fullmatch(name):
            msg = (
                f"operators file {str(path)!r}: entry #{index} has name {name!r}; "
                f"it must be a lowercase slug (letters, digits, `-`, `_`; max 48) "
                f"because it is written verbatim into the audit record."
            )
            raise ConfigurationError(msg)
        if not isinstance(token, str) or not token:
            msg = f"operators file {str(path)!r}: operator {name!r} has no `token`"
            raise ConfigurationError(msg)
        if name in named:
            msg = f"operators file {str(path)!r}: {name!r} appears more than once"
            raise ConfigurationError(msg)
        named[name] = token
    return named
