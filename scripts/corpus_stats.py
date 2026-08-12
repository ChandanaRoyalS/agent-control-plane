#!/usr/bin/env python3
"""What the benign corpus contains, and what the firewall does to it.

    uv run python scripts/corpus_stats.py

The table this prints is the one that belongs in a write-up, and printing it
rather than pasting it means it cannot go stale. It is also the fastest way to
see what a change to a detector did to real documents: run it before and after.

The deployment it screens against is deliberately the realistic one, not the
flattering one — the organisation's own hosts allow-listed and nothing else, and
a catalogue whose tool names appear in its own audit logs, because that is what
an audit log is. Widening either would make the URL, image and tool-mention
detectors silent and the corpus would stop testing them. See ADR 0039.
"""

from __future__ import annotations

import logging
from collections import Counter

from acp.corpus import Corpus, load_attacks, load_benign, load_split
from acp.corpus.evaluate import evaluate
from acp.firewall import Firewall
from acp.upstream.models import CallToolResult, ContentBlock

ALLOWED_HOSTS = frozenset({"wiki.internal", "cdn.internal", "acme.example", "app.acme.example"})
CATALOGUE = frozenset(
    {
        "crm__search",
        "crm__delete_record",
        "docs__read_document",
        "billing__issue_refund",
        "mock-b__delete_record",
    }
)


def screen(corpus: Corpus) -> tuple[Counter[str], Counter[str], list[str]]:
    """``(findings by detector, documents-with-findings by kind, withheld ids)``."""
    firewall = Firewall(enforce=True, allowed_hosts=ALLOWED_HOSTS)
    detectors: Counter[str] = Counter()
    kinds: Counter[str] = Counter()
    withheld: list[str] = []

    for document in corpus.documents:
        result = CallToolResult(
            content=[ContentBlock(type="text", text=document.text)], isError=False
        )
        inspection = firewall.inspect(result, tool="docs__read_document", tools=CATALOGUE)
        if inspection.screening.findings:
            kinds[document.kind] += 1
            for finding in inspection.screening.findings:
                detectors[finding.detector] += 1
        if inspection.refused:
            withheld.append(document.id)

    return detectors, kinds, withheld


def main() -> int:
    # One warning per document with findings, times a hundred documents, is a
    # hundred lines of the thing being counted.
    logging.disable(logging.CRITICAL)
    corpus = load_benign()
    detectors, kinds, withheld = screen(corpus)
    logging.disable(logging.NOTSET)

    total = len(corpus)
    firing = sum(kinds.values())

    print("Benign corpus\n")
    print(f"  documents                 {total}")
    print(f"  kinds                     {len(corpus.kinds)}")
    print(f"  deliberate near-misses    {len(corpus.hard)}")
    print(f"  excerpted from this repo  {len(corpus.found)}")
    print(f"  characters                {sum(d.chars for d in corpus.documents):,}")
    print()

    print("By kind\n")
    for kind, count in sorted(corpus.counts().items()):
        hard = sum(1 for d in corpus.of_kind(kind) if d.hard)
        found = kinds.get(kind, 0)
        print(f"  {kind:<10} {count:>4} docs  {hard:>3} hard  {found:>3} with findings")
    print()

    print("Screened, enforcing, realistic deployment\n")
    print(f"  produced a finding        {firing} ({firing / total:.0%})")
    print(f"  WITHHELD                  {len(withheld)} ({len(withheld) / total:.1%})")
    for document_id in withheld:
        print(f"    - {document_id}")
    print()

    print("Findings by detector\n")
    for detector, count in detectors.most_common():
        print(f"  {detector:<24} {count:>4}")
    print()

    # Not a false-positive rate. The corpus was used while developing, so this
    # number is fitted to it by construction — the honest one needs task 50's
    # held-out split and task 52's confidence intervals.
    print("This is a withheld rate over a corpus that was used while developing.")
    print("It is a floor, not a measurement. See ADR 0039.")
    print()

    attack_failures = attack_scoreboard()
    return 1 if (withheld or attack_failures) else 0


def attack_scoreboard() -> int:
    """The adversarial half: what the firewall does to each attack family.

    Returns the number of attacks whose outcome disagreed with the corpus's
    stated expectation — nonzero is a behaviour change that ADR 0040 says must
    be acknowledged rather than absorbed.
    """
    logging.disable(logging.CRITICAL)
    corpus = load_attacks()
    firewall = Firewall(enforce=True, allowed_hosts=ATTACK_HOSTS)
    board = evaluate(firewall, corpus.attacks, tools=ATTACK_CATALOGUE)
    logging.disable(logging.NOTSET)

    print("Adversarial corpus (W withheld · D detected · U undetected)\n")
    print(f"  attacks                   {len(corpus)}")
    print(f"  families                  {len(corpus.families)}")
    print(f"  uncatchable by design     {len(corpus.undetectable)}")
    print()

    for row in board.rows:
        flag = "" if not row.mismatches else f"  DRIFT: {', '.join(row.mismatches)}"
        print(
            f"  {row.family.value:<20} "
            f"W={row.withheld} D={row.detected} U={row.undetected}   "
            f"catch {row.catch_rate:.0%}{flag}"
        )
    print()

    print("There is no single catch rate on purpose. An aggregate over families")
    print("that includes the uncatchable ones measures the corpus, not the")
    print("firewall. The families are the result. See ADR 0040.")
    print()

    # The held-out split is DESCRIBED here, never scored here. Running the
    # firewall against it during development is exactly the contamination the
    # split exists to prevent — the number it yields belongs to task 52's
    # harness, run deliberately, not to a stats script run on every change.
    split = load_split()
    held = split.heldout
    held_families = sorted({a.family.value for a in held.attacks})
    print()
    print("Held-out split (sealed — described, not scored here)\n")
    print(f"  version                   {split.version}")
    print(f"  held out                  {len(held)}")
    print(f"  development               {len(split.development)}")
    print(f"  families covered          {len(held_families)} of {len(split.development.families)}")
    print()
    print("These attacks are excluded from the development corpus a detector is")
    print("tuned against, so tasks 51-52 can measure the firewall on attacks it")
    print("was never shaped by. See ADR 0041.")
    return len(board.all_mismatches)


ATTACK_HOSTS = frozenset({"docs.corp", "cdn.corp", "acme.example"})
ATTACK_CATALOGUE = frozenset(
    {"mock-a__search", "mock-a__create_ticket", "mock-b__delete_record", "mock-b__summarize"}
)


if __name__ == "__main__":
    raise SystemExit(main())
