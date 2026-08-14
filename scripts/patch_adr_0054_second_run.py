#!/usr/bin/env python3
"""Amend ADR 0054 with the second run, and with what the pair of them says.

    python3 scripts/patch_adr_0054_second_run.py

Two anchors, and **both are checked before either is written** (rule 2d): a
pointer under "The numbers" that a reader cannot miss, and the amendment itself
before "What is counted as overhead that arguably is not".

The ADR is amended in place rather than corrected. The first run is not wrong —
its register states its own premise on the face of the output, which is the
whole point of that register — and deleting it would delete the evidence for the
more useful finding, which is only visible because there are two runs to compare.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TARGET = Path(
    "docs/decisions/0054-an-overhead-number-is-meaningless-without-its-switch-settings.md"
)

MARKER = "## Amendment, 2026-08-14"

# --- anchor 1: a pointer nobody reading the table can miss --------------------

ANCHOR_POINTER = "### The numbers\n"

POINTER = """### The numbers

> **Amended 2026-08-14.** These figures were measured with rate limiting and
> quotas **off** — the defect the register found, three paragraphs above. Bug 81
> turned them on, and the run was repeated before v1.0.0 published anything. The
> second run is at the bottom of this ADR, along with what the pair of them says
> about this harness. The short version: **the multiple is portable and the
> milliseconds are not.**

"""

# --- anchor 2: the amendment itself ------------------------------------------

ANCHOR_AMENDMENT = "## What is counted as overhead that arguably is not\n"

AMENDMENT = """## Amendment, 2026-08-14 — the same measurement, a second time

Everything above was measured against a gateway with `ACP_RATE_LIMIT_ENABLED`
and `ACP_QUOTA_ENABLED` unset. That is the defect this ADR's register found on
its first execution, and ADR 0055 fixed it. So the measurement was repeated on
the merged stack, with both controls on and the register confirming it.

**Two controls were added and every number went down.**

| row | | direct p50 | gateway p50 | added p50 | multiple |
|---|---|---|---|---|---|
| cache miss | first run, budgets **off** | 5.3 ms | 38.1 ms | +32.8 ms | 7.19x |
| | second run, budgets **on** | 3.6 ms | 24.4 ms | **+20.7 ms** | 6.72x |
| cache hit | first run, budgets **off** | 6.8 ms | 22.8 ms | +16.0 ms | 3.35x |
| | second run, budgets **on** | 4.3 ms | 13.7 ms | **+9.4 ms** | 3.19x |

The second run's multiples are printed by the harness; the first run's are
derived from its published medians, because the harness did not print them yet.

### What that means, and what it does not

It does not mean a token bucket makes a gateway faster. Adding a per-call draw
against a bucket and a read of a windowed counter cannot remove work from the
request path. **A negative result that should be impossible is the instrument
talking about itself** (lesson 61, third outing).

So the difference is the machine — and it can be *bounded* rather than waved at.
The gateway's cache-miss median fell by **13.7 ms** while its workload strictly
grew. Since the growth cannot be negative, between-session variation on this
harness is **at least 13.7 ms at p50 — 42% of the headline figure this ADR
published.**

That bound is the finding, and it is a finding about the method rather than the
gateway.

### The discipline that was inherited and did not reach far enough

ADR 0053 learned that one run is a sample wearing a decimal point (lesson 56)
and answered it with three alternating rounds. This ADR inherited that, and §6
says so: three rounds, ten warm-up calls discarded.

Three rounds bound the variation **between rounds of one session**. Nothing here
bounded the variation between sessions — different day, different image build,
a container fleet rebuilt from scratch, and whatever else was running on one
laptop. The ablation's own noise floor came out at 2.1 ms, measured across
restarts *within* a session, and was reported as the limit of the method. **It
is the limit of the method within an afternoon.** Across afternoons the floor is
at least six times higher, and no run printed anything that would have said so.

### The multiple is portable; the milliseconds are not

The two runs disagree about the absolute cost by roughly 40%. They agree about
the ratio to within 6%.

| | first run | second run | disagreement |
|---|---|---|---|
| cache miss, added p50 | +32.8 ms | +20.7 ms | **37%** |
| cache miss, gateway ÷ direct | 7.19x | 6.72x | **6%** |
| cache hit, added p50 | +16.0 ms | +9.4 ms | **41%** |
| cache hit, gateway ÷ direct | 3.35x | 3.19x | **5%** |

The direct call is the control (lesson 59), doing identical work against the
same mock in both runs, and **it moved too**: 5.3 → 3.6 ms and 6.8 → 4.3 ms. A
machine that is a third faster today is a third faster for both paths, so
whatever it varies by largely **divides out of a ratio and does not divide out
of a difference.**

The published headline therefore changes shape. This gateway costs about
**6.7-7.2x a direct call on a cache miss and 3.2-3.4x on a hit**; the
millisecond figures are true of one laptop on two afternoons and are quoted with
their range rather than as a point. `README.md` and `perf/README.md` both say so
now.

This is not an argument that milliseconds are useless — a capacity plan needs
them and a ratio will not do. It is an argument that **the number which survives
leaving this machine is the one whose denominator was measured beside it.**

### A correction to the register's own claim

§1 argues that a performance number is inseparable from the switch settings that
produced it, and prints them so the two cannot be separated by forgetting. That
held: the first run states its premise on the face of the output, which is why it
is amended rather than retracted.

But a reader with both tables in front of them would reasonably conclude that
turning on rate limiting and quotas *saved 12 ms*, and the register does nothing
to stop them. **A register that prevents one wrong conclusion while enabling
another has done half a job.** What is missing is an identity for the run — a
timestamp and a machine — beside the configuration, so that two honest runs
cannot be silently subtracted from each other.

Not fixed here, and named rather than left implicit: it is a change to the
harness's output, this ADR is being amended rather than rewritten, and the
correct place to spend that is the next time the harness is touched.

### And the ladder gained the two rungs it never had

The ablation below has no rung for either budget control, for a reason that was
correct when it was written: **you cannot ablate something that is already off.**
A rung switching off an unset variable measures nothing and reports it as a
step, which is worse than an absence.

Both are now present, appended at the bottom — the right place on the stated
largest-expected-first ordering, and the only placement that leaves every
existing rung's cumulative environment unchanged and therefore every number
already published from this ladder still true of the configuration it names.

The count in "one of five rungs resolved" describes the run it was written
about; the ladder now has seven rungs.

**Both new rungs are predicted to land below the noise floor and print as `·`.**
A token bucket is a clock read and a subtraction; a fixed-window quota is a
dictionary lookup and a comparison. Neither touches the network or the disk, and
the floor is 2.1 ms.

That prediction is written down *before* the run because the interesting outcome
is the one that falsifies it. **A budget control resolving above the floor would
mean it is doing IO, taking a lock, or otherwise serialising the request path** —
none of which its design calls for, and all of which are invisible to every
functional test that exists for it. A prediction of "nothing" is only worth
making when its failure is a diagnosis.

"""


def main() -> int:
    path = ROOT / TARGET
    print("Amending ADR 0054 with the second run.")

    if not path.exists():
        print(f"missing: {path}", file=sys.stderr)
        return 1

    text = path.read_text(encoding="utf-8")

    if MARKER in text:
        print("  already applied")
        print("done.")
        return 0

    # Rule 2d: check EVERY anchor before writing ANY. A patch that lands half of
    # a two-part edit leaves a document that reads as complete and is not.
    missing = [
        name
        for name, anchor in (
            ("the `### The numbers` heading", ANCHOR_POINTER),
            ("the `## What is counted as overhead` heading", ANCHOR_AMENDMENT),
        )
        if anchor not in text
    ]
    if missing:
        msg = (
            f"{TARGET} is missing {', '.join(missing)}, and does not already "
            f"have the change. NOTHING HAS BEEN WRITTEN."
        )
        raise SystemExit(msg)

    text = text.replace(ANCHOR_POINTER, POINTER, 1)
    text = text.replace(ANCHOR_AMENDMENT, AMENDMENT + ANCHOR_AMENDMENT, 1)
    path.write_text(text, encoding="utf-8")

    print("  applied: a pointer under `The numbers`")
    print("  applied: the amendment")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
