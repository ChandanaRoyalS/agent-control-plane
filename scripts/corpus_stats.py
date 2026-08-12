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

from acp.corpus import Corpus, load_benign
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
    return 1 if withheld else 0


if __name__ == "__main__":
    raise SystemExit(main())
