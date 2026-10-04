#!/usr/bin/env python3
"""A purpose-built injection detector from Hugging Face, scored on every corpus.

    make eval-hf-detector
    # which runs, without adding torch to the project's dependencies:
    uv run --with transformers --with torch --with sentencepiece --with protobuf \\
        python scripts/evaluate_hf_detector.py [--model ID] [--threshold 0.5]

The default model is ProtectAI's `deberta-v3-base-prompt-injection-v2`
(Apache-2.0): a binary SAFE / INJECTION classifier, ~184M parameters, CPU-fast.
See `acp.corpus.detector_eval` for what is scored and why. The result is
recorded in an ADR once it has been measured, not before.

**Why `uv run --with` rather than a dependency group.** CI runs `uv sync
--all-groups`; a group containing torch would download about 2 GB on every
build to support a script CI never runs. The detector is an experiment until
its numbers say otherwise, and an experiment does not get to make the build
slower.

Development data only: the 106 benign documents, the 36 internal development
attacks, InjecAgent's development half. No held-out split is read.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Callable
from pathlib import Path

from acp.corpus.detector_eval import DetectorReport, evaluate_detector
from acp.corpus.external import load_external_split
from acp.corpus.harness import DEFAULT_SEED
from acp.corpus.heldout import load_split
from acp.corpus.loader import load_benign
from acp.corpus.metrics import DEFAULT_RESAMPLES

DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
RULE = "=" * 78


def resolved_revision(model_id: str) -> str:
    """The commit of the snapshot that actually loaded, from the local cache.

    `config._commit_hash` is not set by every transformers version (the first
    real run printed "unknown"), and a detector result without the exact
    weights it came from cannot be reproduced. The cache directory is named by
    the commit, so it is read from there, offline.
    """
    try:
        from huggingface_hub import snapshot_download  # noqa: PLC0415

        return Path(snapshot_download(model_id, local_files_only=True)).name
    except Exception:  # a missing revision must not lose the run
        return "unknown"


def load_detector(model_id: str, threshold: float) -> tuple[Callable[[str], bool], str, str]:
    """Return (detect, revision, injection_label). Imports torch lazily so the
    rest of the repository never needs it."""
    try:
        import torch  # noqa: PLC0415
        from transformers import (  # noqa: PLC0415
            AutoModelForSequenceClassification,
            AutoTokenizer,
        )
    except ImportError:
        print(
            "FAILED: transformers and torch are not installed.\n"
            "  Run it as `make eval-hf-detector`, which adds them for this run only.",
            file=sys.stderr,
        )
        raise SystemExit(2) from None

    tokenizer = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForSequenceClassification.from_pretrained(model_id)
    model.eval()
    labels = {int(k): str(v).upper() for k, v in model.config.id2label.items()}
    injection = next(
        (
            i
            for i, name in labels.items()
            if "INJECT" in name or "JAILBREAK" in name or "MALICIOUS" in name
        ),
        None,
    )
    if injection is None:
        print(f"FAILED: cannot tell which label means injection in {labels}", file=sys.stderr)
        raise SystemExit(2)

    def detect(text: str) -> bool:
        encoded = tokenizer(text, truncation=True, max_length=512, return_tensors="pt")
        with torch.no_grad():
            logits = model(**encoded).logits[0]
        probability = torch.softmax(logits, dim=-1)[injection].item()
        return bool(probability >= threshold)

    detect("warm-up")
    revision = resolved_revision(model_id)
    return detect, revision, labels[injection]


def render(report: DetectorReport) -> None:
    print("FALSE POSITIVES — the 106 benign documents")
    print(f"  called an injection     {report.benign_flagged.render()}")

    print("\nINTERNAL ATTACKS — development split, by the family the corpus assigned")
    for row in report.internal:
        print(f"  {row.family.value:<20} {row.detected.render()}")

    print("\nINJECAGENT — development half; caught = yes on the attack, no on its control")
    print(f"  {'slice':<16} {'instr':>5}  {'caught (recall)':<30} said yes")
    for srow in report.external:
        print(
            f"  {srow.label:<16} {srow.groups:>5}  {srow.caught.render():<30} "
            f"{srow.flagged.render()}"
        )
    print(f"  controls called an injection: {report.controls_flagged}")

    lat = report.latency
    print(f"\nLATENCY — {lat.calls} calls, CPU")
    ms = 1000
    print(f"  median {lat.median * ms:.0f} ms   p95 {lat.p95 * ms:.0f} ms", end="")
    print(f"   worst {lat.worst * ms:.0f} ms")

    if report.benign_flagged_ids:
        print(f"\nBENIGN DOCUMENTS CALLED AN INJECTION ({len(report.benign_flagged_ids)})")
        for doc_id in report.benign_flagged_ids:
            print(f"    {doc_id}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--resamples", type=int, default=DEFAULT_RESAMPLES)
    args = parser.parse_args()
    logging.disable(logging.WARNING)

    benign = load_benign().documents
    attacks = load_split().development.attacks
    external = load_external_split().development

    detect, revision, label = load_detector(args.model, args.threshold)
    print(f"{RULE}\nHUGGING FACE DETECTOR — development data only\n{RULE}")
    print(f"  model:     {args.model}")
    print(f"  revision:  {revision}")
    print(f"  decision:  P({label}) >= {args.threshold}\n")

    def progress(done: int, total: int) -> None:
        if done % 200 == 0 or done == total:
            print(f"  ... {done}/{total}", file=sys.stderr, flush=True)

    report = evaluate_detector(
        detect,
        benign=benign,
        attacks=attacks,
        external=external,
        seed=args.seed,
        resamples=args.resamples,
        progress=progress,
    )
    render(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
