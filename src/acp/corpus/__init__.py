"""The evaluation corpus: the documents that turn a claim into a number.

Everything in `acp.firewall` is a mechanism. None of it says how often it is
right, and until something does, "injection firewall" is a description of an
intention. This package is the other half.

Task 48 is the benign half, and it is built first on purpose. The tempting order
is to collect attacks, measure how many are caught, and publish that — a number
anybody can reach by refusing everything. The number that decides whether a
security control survives contact with a real deployment is the other one: how
often it is wrong about a document somebody legitimately needed.

**A benign corpus of tidy text is worse than none**, because it produces a
false-positive rate near zero and the rate is fraudulent. So a third of these
documents are deliberate near-misses — a security advisory quoting a payload,
an emoji family joined by zero-width characters, Arabic carrying directional
marks, a base64 blob in a database row, this repository's own ADRs about prompt
injection — and a test asserts there are enough of them and that the firewall
withholds none of them.

Tasks 49 to 52 add the adversarial corpus sliced by family, a held-out split,
a classifier, and the harness that reports precision, recall and false-positive
rate with confidence intervals. This package is what they all read.

See ADR 0039.
"""

from acp.corpus.document import Document, Source, parse
from acp.corpus.loader import Corpus, default_root, load_benign, load_corpus, repository_root

__all__ = [
    "Corpus",
    "Document",
    "Source",
    "default_root",
    "load_benign",
    "load_corpus",
    "parse",
    "repository_root",
]
