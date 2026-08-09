"""Append the PolicyDeniedError exception to src/acp/exceptions.py.

An asserted patch (standing rule 2): exceptions.py is hand-edited, so this
appends rather than shipping the whole file, and asserts the anchor it appends
after so a moved tail aborts instead of duplicating.

    python3 scripts/patch_exceptions_task34.py
"""

from __future__ import annotations

import sys
from pathlib import Path

EXC = Path("src/acp/exceptions.py")

# Anchor: the last lines of UpstreamRejectedError, which currently end the file.
ANCHOR = (
    "        super().__init__(\n"
    "            message, upstream=upstream, "
    'details={"upstream_code": upstream_code, **(details or {})}\n'
    "        )\n"
    "        self.upstream_code = upstream_code\n"
)

ADDITION = '''

class PolicyDeniedError(ACPError):
    """A policy rule refused this call, or no rule allowed it.

    ``recoverable`` is **false**. Unlike an expired token, a denial is not a
    transient condition the agent can fix by trying again — the principal is not
    entitled to this tool, and retrying the identical call will be refused
    identically. The correct agent behaviour is to stop, not to back off.

    Carries the deciding rule's name in ``details`` for the audit log, or
    ``None`` when the deny default applied. As with ``AuthenticationError``, the
    reason is for the log rather than the caller: telling an agent *which* rule
    denied it, or that a tool exists but is forbidden, is an oracle worth
    denying. From task 35 the tool will not appear in the catalogue at all, so
    the honest answer to the caller is simply that no such tool is available.
    """

    code = -32040
    recoverable = False
'''


def main() -> int:
    if not EXC.exists():
        print(f"{EXC} not found — run from the repo root", file=sys.stderr)
        return 1

    text = EXC.read_text(encoding="utf-8")

    if "class PolicyDeniedError" in text:
        print("PolicyDeniedError already present — nothing to do")
        return 0

    if ANCHOR not in text:
        print(
            "ABORT: the expected tail of exceptions.py was not found. It may have "
            "been edited; add PolicyDeniedError by hand.",
            file=sys.stderr,
        )
        return 1

    if not text.endswith(ANCHOR):
        # The anchor exists but is not the file's tail — appending after the file
        # end would be wrong. Fail rather than guess.
        print(
            "ABORT: UpstreamRejectedError is no longer the last class in the file. "
            "Append PolicyDeniedError by hand after the intended anchor.",
            file=sys.stderr,
        )
        return 1

    EXC.write_text(text + ADDITION, encoding="utf-8")
    print("appended PolicyDeniedError to exceptions.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
