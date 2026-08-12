"""The benign corpus, and the two properties that make it worth having.

The first is the obvious one: **nothing benign is withheld.** That is the
false-positive floor, expressed as a build-breaking assertion rather than as a
number in a README, and it is what demoted two detectors in ADR 0039.

The second is the one a corpus usually lacks: **enough of these documents
actually trip a detector.** A benign corpus of tidy text passes the first
assertion trivially and proves nothing, because the false-positive rate it
implies is a property of the corpus rather than of the firewall. So the build
also fails if the corpus becomes too clean — which is the only defence against
somebody quietly deleting the awkward documents when they start failing.
"""

from __future__ import annotations

import logging

import pytest

from acp.corpus import Corpus, load_benign
from acp.firewall import Firewall
from acp.upstream.models import CallToolResult, ContentBlock

pytestmark = pytest.mark.integration

MIN_DOCUMENTS = 100
MIN_KINDS = 10
MIN_HARD = 25
"""Floors, not targets. A corpus is only ever deleted from by accident, and
these are what makes that accident fail the build."""

MIN_FINDING_RATE = 0.10
"""The anti-filler floor: at least a tenth of benign documents must produce a
finding.

Measured at 19% when the corpus was written. The floor is deliberately well
below that, because this assertion exists to catch a corpus being *replaced*
with tidy text, not to freeze today's detectors — a legitimate reduction in
false positives should not fail the build, and a corpus of documents nothing
fires on should.
"""

ALLOWED_HOSTS = frozenset({"wiki.internal", "cdn.internal", "acme.example", "app.acme.example"})
"""What a realistic deployment allows: its own hosts, and nothing else.

Not the union of every host the corpus mentions — that would make the URL and
image detectors silent and the corpus would stop testing them. This is the list
an organisation actually writes, which is why a third party's newsletter is
still a finding.
"""

CATALOGUE = frozenset(
    {
        "crm__search",
        "crm__delete_record",
        "docs__read_document",
        "billing__issue_refund",
        "mock-b__delete_record",
    }
)
"""A catalogue whose names appear in the corpus, deliberately.

The fair test, not the flattering one. A real gateway's audit log names the real
tools in its real catalogue — that is what an audit log *is* — so a catalogue
disjoint from the corpus would make `tool_name_mention` unable to fire and would
have hidden the false positive that demoted it.
"""


@pytest.fixture(scope="module")
def corpus() -> Corpus:
    return load_benign()


@pytest.fixture(scope="module")
def firewall() -> Firewall:
    return Firewall(enforce=True, allowed_hosts=ALLOWED_HOSTS)


def screen(firewall: Firewall, text: str) -> tuple[bool, int]:
    """``(withheld, findings)`` for one document."""
    result = CallToolResult(content=[ContentBlock(type="text", text=text)], isError=False)
    inspection = firewall.inspect(result, tool="docs__read_document", tools=CATALOGUE)
    return inspection.refused, len(inspection.screening.findings)


# ---------------------------------------------------------------------------
# The floor
# ---------------------------------------------------------------------------


def test_no_benign_document_is_withheld(corpus: Corpus, firewall: Firewall) -> None:
    """The false-positive floor, and the assertion that set ADR 0038's bar.

    It failed the first time it ran. Six documents were withheld: the gateway's
    own audit log, a policy-decision record, its own firewall log lines, an
    audit trail, a marketing newsletter's tracking pixel, and a security
    advisory demonstrating the exfiltration pattern. Two detectors were demoted
    rather than six documents deleted — see ADR 0039.

    Named in `scripts/mutate_refusal.py`: putting a demoted detector back on the
    enforceable list must make *this* test the one that fails.
    """
    with caplog_silent():
        withheld = [d.id for d in corpus.documents if screen(firewall, d.text)[0]]

    assert withheld == [], f"benign documents withheld: {', '.join(withheld)}"


def test_enough_benign_documents_actually_trip_a_detector(
    corpus: Corpus, firewall: Firewall
) -> None:
    """The assertion that makes the one above mean something.

    A corpus of tidy text passes `test_no_benign_document_is_withheld` and
    proves nothing: its false-positive rate is a property of the corpus. So this
    fails the build if the corpus stops being awkward — the only defence against
    somebody deleting the difficult documents when they start failing.
    """
    with caplog_silent():
        firing = sum(1 for d in corpus.documents if screen(firewall, d.text)[1] > 0)

    rate = firing / len(corpus)
    assert rate >= MIN_FINDING_RATE, (
        f"only {rate:.0%} of benign documents produce a finding. A corpus this "
        f"clean measures its own tidiness rather than the firewall's accuracy."
    )


# ---------------------------------------------------------------------------
# The corpus itself
# ---------------------------------------------------------------------------


def test_the_corpus_is_large_enough_to_produce_a_rate(corpus: Corpus) -> None:
    """Below a hundred documents a single false positive moves the rate by more
    than a percentage point, and a rate that granular reads as more precise than
    it is."""
    assert len(corpus) >= MIN_DOCUMENTS


def test_the_corpus_covers_enough_kinds(corpus: Corpus) -> None:
    """One rate over one kind of document is a rate about that kind. The slices
    are what make it a claim about traffic."""
    assert len(corpus.kinds) >= MIN_KINDS


def test_the_corpus_contains_enough_deliberate_near_misses(corpus: Corpus) -> None:
    """The documents that legitimately look like attacks: advisories quoting
    payloads, emoji built from zero-width joiners, Arabic carrying directional
    marks, JWTs, base64 blobs, pages with images on them."""
    assert len(corpus.hard) >= MIN_HARD


def test_some_documents_come_from_the_repository_rather_than_from_imagination(
    corpus: Corpus,
) -> None:
    """The honesty check.

    A corpus invented by the same author as the detectors has a ceiling: that
    author knows what the patterns look for and will, without meaning to, write
    around them. Documents excerpted from this repository cannot have been —
    they were written to be read.
    """
    assert corpus.found, "no document is marked as excerpted from the repository"


def test_every_document_says_why_it_is_here(corpus: Corpus) -> None:
    """A corpus entry nobody can justify is one somebody deletes the first time
    it fails."""
    assert all(document.why for document in corpus.documents)


def test_no_document_is_empty(corpus: Corpus) -> None:
    assert all(document.text.strip() for document in corpus.documents)


def test_every_kind_has_more_than_one_document(corpus: Corpus) -> None:
    """A kind with one document is a slice whose rate is 0% or 100%."""
    thin = [kind for kind, count in corpus.counts().items() if count < 2]
    assert thin == []


def test_the_hard_documents_are_spread_across_kinds(corpus: Corpus) -> None:
    """Near-misses concentrated in one kind would mean the firewall is only
    tested against one shape of awkwardness."""
    kinds = {document.kind for document in corpus.hard}
    assert len(kinds) >= 5


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class caplog_silent:  # noqa: N801 — a context manager used as a verb
    """Screening a hundred documents emits a warning per document with findings.

    Silenced here rather than filtered, because the alternative is a test run
    whose output is two hundred lines of the thing being measured.
    """

    def __enter__(self) -> None:
        logging.disable(logging.CRITICAL)

    def __exit__(self, *_: object) -> None:
        logging.disable(logging.NOTSET)
