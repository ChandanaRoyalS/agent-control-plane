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

Tasks 50 to 52 add the held-out split, a classifier behind the same interface,
and the harness reporting precision, recall and false-positive rate with
confidence intervals per family. Everything reads what is here.
"""

from acp.corpus.attack import Attack, AttackFamily, Expectation, parse_attack
from acp.corpus.document import Document, Source, parse
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

__all__ = [
    "Attack",
    "AttackCorpus",
    "AttackFamily",
    "Corpus",
    "Document",
    "Expectation",
    "HeldoutManifest",
    "Source",
    "Split",
    "default_heldout_path",
    "default_root",
    "load_attacks",
    "load_benign",
    "load_corpus",
    "load_development_attacks",
    "load_heldout_manifest",
    "load_split",
    "parse",
    "parse_attack",
    "repository_root",
    "split_attacks",
]
