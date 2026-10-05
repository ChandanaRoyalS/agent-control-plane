#!/usr/bin/env python3
"""Fine-tune a small transformer on the linear classifier's splits, and score it (ADR 0077).

    make train-transformer                        # fine-tune; writes models/transformer/
    make eval-transformer                         # validation and report-only sets
    make eval-transformer ARGS=--unseal           # the sealed sets, once

Needs PyTorch and transformers, which are deliberately not project dependencies
(the gateway never loads this model); the Makefile adds them with ``uv run --with``.
Runs on Apple-silicon GPUs (MPS), CUDA or CPU.

Everything ADR 0077 fixed before training is in `DESIGN`. A run that departs from
it (``--base``, ``--epochs``, ``--limit``, used for smoke tests) can be trained and
scored on open sets, and is refused by ``--unseal``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import platform
import random
import statistics
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import torch
import transformers
from torch import nn
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from acp.corpus.learned_eval import as_json, open_sets, operating_points, score_sets, sealed_sets
from acp.corpus.loader import default_root, load_benign
from acp.corpus.training import TRANSFORMER_DESIGN, assemble, data_digest, labelled_windows
from acp.firewall.learned import normalise, windows

ROOT = Path(__file__).resolve().parent.parent
MODEL_DIR = ROOT / "models" / "transformer"
RECORD = default_root() / "learned" / "transformer.json"
META = "acp.json"

DESIGN = TRANSFORMER_DESIGN
"""Fixed in ADR 0077 before any training run; ``--unseal`` refuses anything else."""

SCORE_BATCH = 32
LATENCY_CHARS = 10_000


transformers.logging.set_verbosity_error()


def device() -> torch.device:
    if torch.backends.mps.is_available():
        return torch.device("mps")
    if torch.cuda.is_available():
        return torch.device("cuda")
    return torch.device("cpu")


def seed_everything(seed: int) -> None:
    random.seed(seed)
    torch.manual_seed(seed)


@dataclass
class TransformerScorer:
    """Scores a document as its highest window, as the linear model does."""

    model: Any
    tokenizer: Any
    device: torch.device
    max_tokens: int
    threshold: float = 0.5
    enforce_threshold: float = 0.5

    def __post_init__(self) -> None:
        self._cache: dict[str, float] = {}

    @torch.no_grad()
    def window_scores(self, texts: Sequence[str]) -> list[float]:
        self.model.eval()
        order = sorted(range(len(texts)), key=lambda i: len(texts[i]))
        scores = [0.0] * len(texts)
        for start in range(0, len(order), SCORE_BATCH):
            batch = order[start : start + SCORE_BATCH]
            encoded = self.tokenizer(
                [texts[i] for i in batch],
                truncation=True,
                max_length=self.max_tokens,
                padding=True,
                return_tensors="pt",
            ).to(self.device)
            probs = torch.softmax(self.model(**encoded).logits.float(), dim=-1)[:, 1]
            for i, p in zip(batch, probs.tolist(), strict=True):
                scores[i] = p
        return scores

    def score_documents(self, documents: Sequence[str]) -> list[float]:
        owners: list[int] = []
        texts: list[str] = []
        for d, document in enumerate(documents):
            for _, window in windows(normalise(document)):
                owners.append(d)
                texts.append(window)
        best = [0.0] * len(documents)
        for d, s in zip(owners, self.window_scores(texts), strict=True):
            best[d] = max(best[d], s)
        return best

    def prime(self, documents: Sequence[str]) -> None:
        """Score many documents in batches, so `score` is a lookup."""
        todo = [d for d in dict.fromkeys(documents) if d not in self._cache]
        self._cache.update(zip(todo, self.score_documents(todo), strict=True))

    def score(self, text: str) -> float:
        if text not in self._cache:
            self.prime([text])
        return self._cache[text]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def weights_file(model_dir: Path) -> Path:
    found = sorted(model_dir.glob("*.safetensors"))
    if len(found) != 1:
        msg = f"expected one .safetensors file in {model_dir}, found {len(found)}"
        raise SystemExit(msg)
    return found[0]


# -- training -----------------------------------------------------------------


def fine_tune(
    model: Any,
    tokenizer: Any,
    texts: list[str],
    labels: list[int],
    *,
    config: dict[str, Any],
    run_on: torch.device,
) -> tuple[list[float], float]:
    """Train in place with class-balanced loss; returns mean loss per epoch and seconds."""
    positives = sum(labels)
    negatives = len(labels) - positives
    class_weights = torch.tensor(
        [len(labels) / (2 * negatives), len(labels) / (2 * positives)], device=run_on
    )
    loss_fn = nn.CrossEntropyLoss(weight=class_weights)
    optimiser = torch.optim.AdamW(
        model.parameters(), lr=config["learning_rate"], weight_decay=config["weight_decay"]
    )
    steps_per_epoch = -(-len(texts) // config["batch_size"])
    total_steps = steps_per_epoch * config["epochs"]
    schedule = transformers.get_linear_schedule_with_warmup(
        optimiser, int(config["warmup_share"] * total_steps), total_steps
    )

    order = list(range(len(texts)))
    shuffler = random.Random(config["seed"])  # noqa: S311 — reproducibility
    started = time.monotonic()
    losses: list[float] = []
    for epoch in range(config["epochs"]):
        model.train()
        shuffler.shuffle(order)
        epoch_losses: list[float] = []
        for start in range(0, len(order), config["batch_size"]):
            batch = order[start : start + config["batch_size"]]
            encoded = tokenizer(
                [texts[i] for i in batch],
                truncation=True,
                max_length=config["max_tokens"],
                padding=True,
                return_tensors="pt",
            ).to(run_on)
            target = torch.tensor([labels[i] for i in batch], device=run_on)
            loss = loss_fn(model(**encoded).logits, target)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimiser.step()
            schedule.step()
            optimiser.zero_grad()
            epoch_losses.append(loss.item())
        losses.append(statistics.fmean(epoch_losses))
        print(f"epoch {epoch + 1}: mean loss {losses[-1]:.4f}", file=sys.stderr)
    train_seconds = time.monotonic() - started
    return losses, train_seconds


def train(args: argparse.Namespace) -> int:
    config = {
        **DESIGN,
        "base": args.base,
        "epochs": args.epochs,
        "limit": args.limit,
    }
    seed_everything(config["seed"])
    data = assemble()
    train_set, validation = list(data.train), list(data.validation)
    labelled = labelled_windows(train_set)
    texts, labels = labelled.texts, labelled.labels
    if args.limit:
        rng = random.Random(config["seed"])  # noqa: S311 — reproducibility
        keep = sorted(rng.sample(range(len(texts)), min(args.limit, len(texts))))
        texts, labels = [texts[i] for i in keep], [labels[i] for i in keep]
        validation = validation[: args.limit]
    run_on = device()
    print(f"{len(texts)} windows ({sum(labels)} positive) on {run_on}", file=sys.stderr)

    tokenizer = AutoTokenizer.from_pretrained(config["base"])
    model = AutoModelForSequenceClassification.from_pretrained(config["base"], num_labels=2)
    model.to(run_on)
    lengths = [len(ids) for ids in tokenizer(texts, truncation=False)["input_ids"]]
    truncated = sum(n > config["max_tokens"] for n in lengths)

    losses, train_seconds = fine_tune(model, tokenizer, texts, labels, config=config, run_on=run_on)

    scorer = TransformerScorer(model, tokenizer, run_on, config["max_tokens"])
    benign = scorer.score_documents([e.text for e in validation if e.label == 0])
    attacks = scorer.score_documents([e.text for e in validation if e.label == 1])
    points = operating_points(benign, attacks)
    print(
        f"report threshold {points.threshold:.3f}: validation recall {points.recall:.1%}, "
        f"fpr {points.fpr:.1%}; enforce {points.enforce_threshold:.3f}: "
        f"recall {points.enforce_recall:.1%}",
        file=sys.stderr,
    )

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(out)
    tokenizer.save_pretrained(out)
    meta = {
        "design": config,
        "threshold": points.threshold,
        "enforce_threshold": points.enforce_threshold,
        "validation": {"recall": round(points.recall, 4), "fpr": round(points.fpr, 4)},
        "validation_enforce": {"recall": round(points.enforce_recall, 4), "fpr": 0.0},
        "train_windows": len(texts),
        "train_windows_truncated": truncated,
        "epoch_losses": [round(x, 4) for x in losses],
        "train_seconds": round(train_seconds, 1),
        "device": str(run_on),
        "train_digest": data_digest(train_set),
        "validation_digest": data_digest(data.validation),
        "weights_sha256": sha256(weights_file(out)),
        "versions": {
            "python": platform.python_version(),
            "torch": torch.__version__,
            "transformers": transformers.__version__,
            "platform": f"{platform.system()} {platform.machine()}",
        },
    }
    (out / META).write_text(json.dumps(meta, indent=1) + "\n", encoding="utf-8")
    print(f"Wrote {out}", file=sys.stderr)
    return 0


# -- evaluation ---------------------------------------------------------------


def load(model_dir: Path) -> tuple[TransformerScorer, dict[str, Any]]:
    meta = json.loads((model_dir / META).read_text(encoding="utf-8"))
    if sha256(weights_file(model_dir)) != meta["weights_sha256"]:
        msg = f"{model_dir}: the weights are not the ones that were trained and thresholded"
        raise SystemExit(msg)
    run_on = device()
    tokenizer = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(model_dir).to(run_on)
    scorer = TransformerScorer(
        model,
        tokenizer,
        run_on,
        meta["design"]["max_tokens"],
        threshold=meta["threshold"],
        enforce_threshold=meta["enforce_threshold"],
    )
    return scorer, meta


def latency(scorer: TransformerScorer) -> dict[str, float]:
    """Median milliseconds per thousand characters, on this device and on CPU."""
    text = "\n\n".join(d.text for d in load_benign().documents)[:LATENCY_CHARS]
    out: dict[str, float] = {}
    for name, where in ((str(scorer.device), scorer.device), ("cpu", torch.device("cpu"))):
        scorer.model.to(where)
        probe = TransformerScorer(scorer.model, scorer.tokenizer, where, scorer.max_tokens)
        probe.score_documents([text])  # warm-up
        times = []
        for _ in range(5):
            started = time.perf_counter()
            probe.score_documents([text])
            times.append(time.perf_counter() - started)
        out[name] = round(statistics.median(times) * 1000 / (len(text) / 1000), 2)
    scorer.model.to(scorer.device)
    return out


def evaluate(args: argparse.Namespace) -> int:
    logging.disable(logging.CRITICAL)  # the firewall logs every screening
    model_dir = Path(args.model_dir)
    record_path = Path(args.record)
    scorer, meta = load(model_dir)
    existing = json.loads(record_path.read_text()) if record_path.exists() else {}
    if args.unseal:
        if existing.get("sealed"):
            msg = (
                f"the sealed sets were already scored for this design, with weights "
                f"{existing['sealed_on'][:12]}; refusing another look"
            )
            raise SystemExit(msg)
        if meta["design"] != DESIGN:
            msg = "this run departs from ADR 0077's design; it may not see the sealed sets"
            raise SystemExit(msg)

    data = assemble(unseal=args.unseal)
    if (meta["train_digest"], meta["validation_digest"]) != (
        data_digest(data.train),
        data_digest(data.validation),
    ):
        msg = "the corpora or splits changed since this model was trained; retrain it"
        raise SystemExit(msg)

    sets = open_sets(data)
    scorer.prime([e.text for members in sets.values() for e in members])
    rows = score_sets(sets, scorer)
    for row in as_json(rows):
        print(row["set"], row["kind"], row["learned"], row["learned_enforce"])
    record: dict[str, Any] = {
        "model": {k: v for k, v in meta.items() if k not in ("threshold", "enforce_threshold")},
        "threshold": meta["threshold"],
        "enforce_threshold": meta["enforce_threshold"],
        "latency_ms_per_1k_chars": latency(scorer),
        "open": as_json(rows),
        "sealed": existing.get("sealed", []),
        "sealed_on": existing.get("sealed_on"),
        "second_look": (
            "BIPIA test and evasion v1 were first scored for the linear model (ADR 0075); "
            "this design was fixed before this model saw them (ADR 0077)"
        ),
    }
    if args.unseal:
        sealed = sealed_sets(data)
        scorer.prime([e.text for members in sealed.values() for e in members])
        sealed_rows = score_sets(sealed, scorer)
        print("\nSEALED, scored once:")
        for row in as_json(sealed_rows):
            print(row["set"], row["kind"], row["learned"], row["learned_enforce"])
        record["sealed"] = as_json(sealed_rows)
        record["sealed_on"] = meta["weights_sha256"]

    record_path.parent.mkdir(parents=True, exist_ok=True)
    record_path.write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
    print(f"\nWrote {record_path}", file=sys.stderr)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__ and __doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    fit = commands.add_parser("train", help="fine-tune and choose thresholds on validation")
    fit.add_argument("--base", default=DESIGN["base"], help="a Hugging Face model id or path")
    fit.add_argument("--epochs", type=int, default=DESIGN["epochs"])
    fit.add_argument("--limit", type=int, help="train on this many windows (smoke tests)")
    fit.add_argument("--out", default=str(MODEL_DIR))
    score = commands.add_parser("evaluate", help="score open sets; --unseal for sealed, once")
    score.add_argument("--model-dir", default=str(MODEL_DIR))
    score.add_argument("--record", default=str(RECORD))
    score.add_argument("--unseal", action="store_true")
    args = parser.parse_args()
    return train(args) if args.command == "train" else evaluate(args)


if __name__ == "__main__":
    raise SystemExit(main())
