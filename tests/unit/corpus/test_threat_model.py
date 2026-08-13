"""The threat model's numbers must be the measured ones — task 59.

`docs/THREAT_MODEL.md` is the document a reader is most likely to *believe*
without checking, because prose reads as authoritative in a way a JSON file
does not. It is also the document most likely to rot: the corpus grows, a
detector is demoted, `make eval --capture` accepts a new baseline, and the
write-up keeps quoting last month's recall to whoever reads it next.

**A security document whose numbers have silently drifted is worse than one
with no numbers**, because it spends credibility it no longer has. So the
tables are parsed out of the Markdown and diffed against
`corpus/eval-baseline.json` — the same committed artifact `make eval-check`
gates on.

This is lesson 34 (*documentation numbers must come from the shipped
defaults*) applied to the one document where being wrong is most expensive,
and it is the same argument ADR 0013 makes for schema drift and ADR 0047 for
the evaluation gate: **a claim worth making is worth failing the build over.**

What this deliberately does *not* check: the prose. A test cannot tell whether
"under half of what this firewall flags is an attack" is still a fair summary.
It can tell whether the table it summarises still matches the measurement, and
that is the part that goes stale silently.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
THREAT_MODEL = ROOT / "docs" / "THREAT_MODEL.md"
BASELINE = ROOT / "corpus" / "eval-baseline.json"

# | exfiltration | 5/5 | 0 |          — bold markers optional, families are bolded
# | **plain_assertion** | **0/6** | 0 |  when the number is one worth staring at
DETECTION_ROW = re.compile(
    r"^\|\s*\*{0,2}([a-z_]+)\*{0,2}\s*\|\s*\*{0,2}(\d+)/(\d+)\*{0,2}\s*\|\s*\*{0,2}(\d+)\*{0,2}\s*\|$",
    re.M,
)

# | obfuscation | 67% (6/9) | [33%, 89%] |
PRECISION_ROW = re.compile(
    r"^\|\s*([a-z_]+)\s*\|\s*\*{0,2}(\d+)%\s*\((\d+)/(\d+)\)\*{0,2}\s*\|\s*\*{0,2}\[",
    re.M,
)


def baseline() -> dict[str, Any]:
    payload: dict[str, Any] = json.loads(BASELINE.read_text(encoding="utf-8"))
    return payload


def document() -> str:
    return THREAT_MODEL.read_text(encoding="utf-8")


def test_the_threat_model_exists_and_is_not_a_stub() -> None:
    """It was a stub from Phase 1 to Phase 7, deliberately. It is not one now,
    and a regression to one should be loud rather than quiet."""
    text = document()
    assert "**Status:** stub" not in text
    assert "To be completed in Phase 7" not in text


def test_every_attack_family_appears_in_the_detection_table() -> None:
    """A family measured but not written down is the drift that matters most —
    it is always the embarrassing one that goes missing."""
    families = set(baseline()["families"])
    written = {match[0] for match in DETECTION_ROW.findall(document())}
    assert families <= written, f"not in the threat model: {sorted(families - written)}"


def test_the_detection_table_matches_the_measured_baseline() -> None:
    """Detected, total and withheld, per family, exactly as measured."""
    measured = baseline()["families"]
    for family, detected, total, withheld in DETECTION_ROW.findall(document()):
        if family not in measured:
            continue  # a row from some other table that happens to parse
        row = measured[family]
        assert (int(detected), int(total), int(withheld)) == (
            row["detected"],
            row["total"],
            row["withheld"],
        ), (
            f"{family}: the threat model says {detected}/{total} detected, "
            f"{withheld} withheld; the baseline measured "
            f"{row['detected']}/{row['total']}, {row['withheld']} withheld"
        )


def test_the_families_caught_at_zero_are_still_named_as_zero() -> None:
    """The two rows a future edit is most tempted to soften.

    `plain_assertion` and `delayed_multi_step` are detected at a rate of zero,
    and the threat model says so in bold. If a later corpus change makes that
    untrue the test fails and the claim gets *strengthened*; if somebody edits
    the claim without the measurement moving, it fails too.
    """
    measured = baseline()["families"]
    rows = {m[0]: (int(m[1]), int(m[2])) for m in DETECTION_ROW.findall(document())}
    for family in ("plain_assertion", "delayed_multi_step"):
        assert measured[family]["detected"] == 0, (
            f"{family} is no longer detected at zero — the threat model's "
            f"claim is now understated, which is the good direction, but it "
            f"still has to be rewritten"
        )
        assert rows[family] == (0, measured[family]["total"])


def test_the_precision_table_matches_the_measured_hits() -> None:
    """Precision is `attack_hits / (attack_hits + benign_hits)` per family, and
    the fraction in the document must be that pair rather than a rounded
    percentage somebody re-derived by hand."""
    reported = baseline()["reported"]
    seen = set()
    for family, percent, hits, flagged in PRECISION_ROW.findall(document()):
        if family not in reported:
            continue
        row = reported[family]
        total = row["attack_hits"] + row["benign_hits"]
        assert (int(hits), int(flagged)) == (row["attack_hits"], total), (
            f"{family}: the threat model says {hits}/{flagged}; the baseline "
            f"measured {row['attack_hits']}/{total}"
        )
        assert int(percent) == round(100 * row["attack_hits"] / total), (
            f"{family}: {percent}% does not round from {hits}/{flagged}"
        )
        seen.add(family)
    assert seen == set(reported), f"precision rows missing: {sorted(set(reported) - seen)}"


def test_the_benign_numbers_are_the_measured_ones() -> None:
    """The load-bearing claim in the whole document.

    "0 of 106 benign documents withheld" is what makes a firewall with 42%
    precision survivable — the bar between *found something* and *acted on it*
    is carrying the deployment. If that zero ever moves, this sentence stops
    being an argument and becomes an admission.
    """
    benign = baseline()["benign"]
    text = document()
    assert f"**{benign['withheld']} of {benign['total']} benign documents withheld**" in text
    assert f"{benign['total']} benign" in text


def test_the_held_out_split_is_described_as_unscored() -> None:
    """The most easily-lost caveat in the document.

    Every rate quoted is fitted to corpora consulted while writing the
    detectors. The held-out split exists precisely to answer whether that
    fitting generalises, and it has never been run — so the threat model must
    keep saying so until somebody scores it.
    """
    text = document()
    assert "has never been scored" in text
    assert "--unseal" in text


def test_the_out_of_scope_list_is_not_empty() -> None:
    """A threat model with nothing out of scope has not been thought about.

    The section is what makes "we did not think of it" and "we decided against
    it" distinguishable from outside, which is the document's stated purpose.
    """
    text = document()
    section = text.split("## 8. Explicitly out of scope", 1)[-1].split("## 9.", 1)[0]
    bullets = [line for line in section.splitlines() if line.startswith("- **")]
    assert len(bullets) >= 5, "the out-of-scope list has been trimmed to near-nothing"
