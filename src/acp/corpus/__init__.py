"""The evaluation corpus that turns firewall claims into numbers.

Benign documents first (ADR 0039), attacks sliced by family with an expected
outcome each (ADR 0040), a held-out split not tuned against (ADR 0041), a model
classifier (ADR 0042), a harness reporting FP rate, recall and precision with
bootstrap intervals and no aggregate rate (ADR 0046), and a committed baseline
compared by counts (ADR 0047).
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
