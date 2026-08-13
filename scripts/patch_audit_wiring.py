#!/usr/bin/env python3
"""Give the composed stack, `make` and CI an audit chain. Asserted, idempotent.

`docker-compose.yml`, `Makefile`, `.github/workflows/ci.yml` and `.gitignore` are
never shipped whole. **Every anchor is checked before anything is written**, so a
half-wired repository is not a state this can produce.

Tasks 56 and 57 shipped complete and tested with no demo path — the exact trap
task 55 was about, deferred deliberately rather than rushed. This closes it.

**Why the log is a host-mounted directory rather than a named volume.** The whole
value of task 57 is that a person can run `acp audit verify` against the artifact.
A named volume puts it somewhere only Docker can reach, which makes the verifier
a thing you have to `docker exec` to use — and a verifier that is awkward to run
is one that runs after an incident rather than before. `./audit` is writable by
the container and readable by the host, so the command in the README is the
command that works.

**And `config/` stays read-only, which is why the checkpoint lives there.** The
gateway can write its chain and cannot write the anchor that proves it has not
rewritten the chain. That separation is the entire point of ADR 0050's decision 5,
and it falls out of a mount option rather than out of anybody's discipline.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# --- docker-compose.yml -----------------------------------------------------

COMPOSE_ENV_ANCHOR = '      ACP_APPROVAL_MAX_PENDING: "256"\n'

COMPOSE_ENV = """      # -- the tamper-evident audit chain (tasks 56, 57) -------------------
      #
      # Presence of the path is what enables it; there is deliberately no
      # default, because an evidentiary artifact appearing in somebody's working
      # directory the first time they run the gateway is one that gets
      # gitignored, then forgotten.
      #
      # /app/audit is a HOST-MOUNTED directory, not a named volume, so
      # `acp audit verify` can be run by a person rather than through
      # `docker exec`. A verifier that is awkward to run is one that runs after
      # an incident instead of before.
      ACP_AUDIT_FILE: /app/audit/audit.jsonl
      # Fail closed: a call this gateway cannot record does not happen. An audit
      # log that stops recording while the gateway keeps serving is worse than
      # none, because the record then asserts by omission that nothing happened
      # during the window somebody will eventually ask about.
      ACP_AUDIT_REQUIRED: "true"
"""

COMPOSE_VOLUME_ANCHOR = "      - ./config:/app/config:ro\n"

COMPOSE_VOLUME = """      #
      # Writable, and the only writable mount this container has. The chain goes
      # here; the CHECKPOINT that anchors it goes in `config/` above, which is
      # read-only — so the gateway can write its own log and cannot write the
      # thing that proves it has not rewritten that log. ADR 0050 argues the
      # anchor is worth exactly the distance between it and the writer, and this
      # is that distance expressed as a mount option rather than as discipline.
      - ./audit:/app/audit
"""

# --- Makefile ---------------------------------------------------------------

MAKE_ANCHOR = "smoke:  ## Assert the composed stack actually works\n"

MAKE_TARGET = """audit-verify:  ## Walk the composed stack's chain, checked against the anchor
\tuv run acp audit verify --log-file audit/audit.jsonl

audit-checkpoint:  ## Anchor the chain at its current head, then COMMIT the result
\tuv run acp audit checkpoint --log-file audit/audit.jsonl

"""

# --- CI ---------------------------------------------------------------------

CI_ANCHOR = "        run: python scripts/compose_smoke.py\n"

CI_STEP = """
      # The chain a REAL gateway wrote, verified by the real verifier. Every unit
      # test in tests/unit/audit would still pass if the gateway never called the
      # audit log at all, and every integration test drives an in-process app —
      # this is the only place the artifact is produced by a container and
      # checked from outside it.
      - name: Verify the audit chain the composed gateway wrote
        run: uv run acp audit verify --log-file audit/audit.jsonl
"""

# --- .gitignore -------------------------------------------------------------

IGNORE_ANCHOR = "config/secrets.enc\n"

IGNORE_ENTRY = """
# The composed stack's audit chain. Never committed: it is per-run evidence, it
# grows without bound, and a chain in git would make every `git checkout` a
# rewrite of an audit log — which is precisely what the chain exists to detect.
# The CHECKPOINT that anchors it *is* committed, and lives in config/.
audit/
"""


def edit(path: Path, anchor: str, replacement: str, *, label: str) -> bool:
    text = path.read_text(encoding="utf-8")
    if replacement in text:
        print(f"  already applied: {label}")
        return False
    path.write_text(text.replace(anchor, replacement, 1), encoding="utf-8")
    print(f"  applied: {label}")
    return True


EDITS = (
    ("docker-compose.yml", COMPOSE_ENV_ANCHOR, COMPOSE_ENV_ANCHOR + COMPOSE_ENV, "audit settings"),
    (
        "docker-compose.yml",
        COMPOSE_VOLUME_ANCHOR,
        COMPOSE_VOLUME_ANCHOR + COMPOSE_VOLUME,
        "a writable mount for the chain",
    ),
    ("Makefile", MAKE_ANCHOR, MAKE_TARGET + MAKE_ANCHOR, "make audit-verify / audit-checkpoint"),
    (".github/workflows/ci.yml", CI_ANCHOR, CI_ANCHOR + CI_STEP, "CI verifies the chain"),
    (
        ".gitignore",
        IGNORE_ANCHOR,
        IGNORE_ANCHOR + IGNORE_ENTRY,
        "ignore the chain, keep the anchor",
    ),
)


def main() -> int:
    print("Wiring the audit chain into compose, make, CI and .gitignore.")

    # Every anchor checked before anything is written. A half-wired repository
    # would be worse than an unwired one: `make audit-verify` against a stack
    # that writes no chain reports "no audit log", which reads as a bug in the
    # feature rather than a patch that stopped halfway.
    for name, anchor, replacement, label in EDITS:
        path = ROOT / name
        if not path.exists():
            print(f"missing: {path}", file=sys.stderr)
            return 1
        text = path.read_text(encoding="utf-8")
        if replacement not in text and anchor not in text:
            msg = (
                f"{name} does not contain the anchor for {label!r}, and does not "
                f"already have the change. NOTHING HAS BEEN WRITTEN. Check that "
                f"this branch is at task 57."
            )
            raise SystemExit(msg)

    for name, anchor, replacement, label in EDITS:
        edit(ROOT / name, anchor, replacement, label=label)

    # 0o777, and it needs a paragraph rather than a shrug.
    #
    # The image runs as `USER acp`, uid 10001 (Dockerfile), which is correct: a
    # gateway that brokers for an agent fleet should not be root. A bind mount
    # preserves the HOST's ownership, so a directory created here belongs to
    # whoever ran the patch — and the container cannot write to it. The sink
    # then fails to open, which is FATAL by design (ADR 0050: a gateway
    # configured to keep a record and unable to must not serve), and the symptom
    # is `container acp-gateway is unhealthy` with the real reason in the logs.
    #
    # The alternatives are worse for a dev stack: `user:` in compose pinned to
    # the host's uid stops the file being portable between machines, and running
    # the container as root to fix a permissions problem is how a container ends
    # up running as root. A world-writable directory in a gitignored dev
    # scratch space is the small, visible cost.
    #
    # A real deployment does not do this. It gives the container a volume whose
    # ownership it controls, and `ACP_AUDIT_FILE` points at that.
    audit = ROOT / "audit"
    audit.mkdir(exist_ok=True)
    audit.chmod(0o777)
    print("  created: audit/ (gitignored, world-writable — see the note in this script)")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
