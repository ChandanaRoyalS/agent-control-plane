"""The evaluation corpus: the documents that turn a claim into a number.

Everything in `acp.firewall` is a mechanism. None of it says how often it is
right, and until something does, "injection firewall" is a description of an
intention. This package is the other half.

**Benign first, deliberately** (task 48, ADR 0039). The tempting order is to
collect attacks, count how many are caught, and publish that — a number anybody
can reach by refusing everything. The number that decides whether a security
control survives a real deployment is how often it is wrong about a document
somebody legitimately needed. Building that half first meant the first
measurement this project ever produced was one that made it weaker: it demoted
two detectors within an hour, including the one described as having a
false-positive rate near zero.

**Then the attacks, sliced by family** (task 49, ADR 0040). A single detection
rate over mixed attacks is unreadable, so every attack names its family — and
the taxonomy deliberately includes two families no detector can catch, because a
taxonomy containing only what you can catch is a taxonomy that flatters you.
Every attack also records what the firewall is expected to do with it, including
`undetected`, and the build fails when an expectation is wrong in *either*
direction.

**Then the split that may not be tuned against** (task 50, ADR 0041) and a
model classifier behind the same detector interface (task 51, ADR 0042).

**Then the harness that turns all of it into numbers** (task 52, ADR 0046).
False-positive rate first, then recall sliced by the family the
corpus assigned, then precision sliced by the family the firewall reported —
two different questions over two different populations, reported as two tables
so nobody divides one by the other. Every rate carries a bootstrap interval,
because a rate over 106 documents and a rate over 106,000 read identically and
are not the same claim. There is still no aggregate detection rate, and the
held-out split is named and counted on every run and scored on none of them
without a deliberate flag.

**And finally the gate that keeps the numbers from quietly getting worse**
(task 53, ADR 0047). A committed baseline rather than a threshold, compared by
counts rather than rates, so accepting a regression stays possible and stops
being invisible — it becomes a diff in a pull request with a person's name on
it.
"""

from acp.corpus.attack import Attack, AttackFamily, Expectation, parse_attack
from acp.corpus.baseline import (
    Baseline,
    Comparison,
    baseline_from,
    compare,
    default_baseline_path,
    load_baseline,
)
from acp.corpus.document import Document, Source, parse
from acp.corpus.harness import (
    DEFAULT_DEPLOYMENT,
    Deployment,
    PrecisionRow,
    RecallRow,
    Report,
    evaluate_firewall,
)
from acp.corpus.heldout import (
    HeldoutManifest,
    Split,
    default_heldout_path,
    load_development_attacks,
    load_heldout_manifest,
    load_split,
    split_attacks,
)
from acp.corpus.loader import (
    AttackCorpus,
    Corpus,
    default_root,
    load_attacks,
    load_benign,
    load_corpus,
    repository_root,
)
from acp.corpus.metrics import Interval, Proportion, bootstrap, measure

__all__ = [
    "DEFAULT_DEPLOYMENT",
    "Attack",
    "AttackCorpus",
    "AttackFamily",
    "Baseline",
    "Comparison",
    "Corpus",
    "Deployment",
    "Document",
    "Expectation",
    "HeldoutManifest",
    "Interval",
    "PrecisionRow",
    "Proportion",
    "RecallRow",
    "Report",
    "Source",
    "Split",
    "baseline_from",
    "bootstrap",
    "compare",
    "default_baseline_path",
    "default_heldout_path",
    "default_root",
    "evaluate_firewall",
    "load_attacks",
    "load_baseline",
    "load_benign",
    "load_corpus",
    "load_development_attacks",
    "load_heldout_manifest",
    "load_split",
    "measure",
    "parse",
    "parse_attack",
    "repository_root",
    "split_attacks",
]
