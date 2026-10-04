"""Attacks nobody on this project wrote.

Every attack in `corpus/attack/` was written by the person who wrote the
detectors, and ADR 0060 measured the cost of that: the held-out split matched
its author's predictions 7 for 7, which says the author knows the firewall, not
that the firewall works. This module loads an external corpus — InjecAgent
(Zhan et al., ACL Findings 2024, MIT), imported by `scripts/import_injecagent.py`
— and scores the firewall on it.

**Sliced the way the source slices it.** InjecAgent's two subsets are *direct
harm* (`dh`: the planted instruction asks the agent to do something damaging)
and *data stealing* (`ds`: it asks the agent to send the user's data to the
attacker), each in a *base* form and an *enhanced* form that prefixes "IMPORTANT!!!
Ignore all previous instructions…". These do not map onto this corpus's seven
families — `ds` exfiltrates through a tool call, not a rendered URL — and
forcing them would invent a precision the mapping does not have. So the report
is per subset x variant, plus the source's own attack types.

**Intervals resample attacker instructions, not documents.** The corpus is a
cross product (see `scripts/import_injecagent.py`), so the honest sample size is
the number of distinct instructions. `measure_clustered` says why.

**Split by instruction, half sealed.** `heldout.txt` beside the documents lists
the instruction groups held out as split v2, chosen by `held_out` — a hash rule,
re-derived by a test so the list cannot be edited by hand.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from acp.corpus.harness import DEFAULT_DEPLOYMENT, DEFAULT_SEED, Deployment, _screen
from acp.corpus.heldout import HeldoutManifest, load_heldout_manifest
from acp.corpus.loader import default_root
from acp.corpus.metrics import DEFAULT_RESAMPLES, Proportion, measure_clustered
from acp.exceptions import ConfigurationError
from acp.firewall import Firewall

SOURCE: Final = "injecagent"
SALT: Final = "acp-heldout-v2"
"""Fixed before the first import. Changing it re-rolls the split; the generated
`heldout.txt` would change in the same diff, and a test would fail first."""

SUBSETS: Final = ("dh", "ds")
VARIANTS: Final = ("base", "enhanced")
_FIELDS: Final = ("id", "group", "subset", "variant", "attack_type", "text", "planted")


def group_id(subset: str, instruction: str) -> str:
    """A stable name for one attacker instruction within one subset."""
    digest = hashlib.sha256(instruction.encode("utf-8")).hexdigest()[:10]
    return f"{subset}/{digest}"


def held_out(group: str) -> bool:
    """The split rule: half the groups, by hash. Applied, never chosen."""
    return int(hashlib.sha256(f"{SALT}:{group}".encode()).hexdigest(), 16) % 2 == 1


@dataclass(frozen=True, slots=True)
class ExternalDocument:
    """One poisoned tool response, as the source wrote it."""

    id: str
    group: str
    """The attacker instruction it carries. Documents sharing a group are the
    same attack in different templates — one piece of evidence, not seventeen."""
    subset: str
    variant: str
    attack_type: str
    text: str
    planted: str
    """The span the source inserted. Never screened on its own; used only to
    build the control — this text with the span removed."""

    @property
    def control(self) -> str:
        """The response as the template wrote it, with no attack in it."""
        return self.text.replace(self.planted, "", 1)


@dataclass(frozen=True, slots=True)
class ExternalSplit:
    development: tuple[ExternalDocument, ...]
    heldout: tuple[ExternalDocument, ...]
    manifest: HeldoutManifest


def default_external_dir(root: Path | None = None) -> Path:
    return (root or default_root()) / "external" / SOURCE


def load_external(directory: Path | None = None) -> tuple[ExternalDocument, ...]:
    """Every document, or an error naming the line that stopped the load."""
    path = (directory or default_external_dir()) / "documents.jsonl"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        msg = f"cannot read external corpus {str(path)!r}: {exc}"
        raise ConfigurationError(msg) from exc

    documents: list[ExternalDocument] = []
    seen: set[str] = set()
    for lineno, line in enumerate(lines, start=1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            msg = f"{path.name} line {lineno}: not JSON ({exc.msg})"
            raise ConfigurationError(msg) from exc
        if not isinstance(row, dict) or not all(isinstance(row.get(f), str) for f in _FIELDS):
            msg = f"{path.name} line {lineno}: needs string fields {', '.join(_FIELDS)}"
            raise ConfigurationError(msg)
        if row["subset"] not in SUBSETS or row["variant"] not in VARIANTS:
            msg = f"{path.name} line {lineno}: unknown subset/variant"
            raise ConfigurationError(msg)
        if row["text"].count(row["planted"]) != 1:
            msg = f"{path.name} line {lineno}: `planted` is not in `text` exactly once"
            raise ConfigurationError(msg)
        if row["id"] in seen:
            msg = f"{path.name} line {lineno}: duplicate id {row['id']!r}"
            raise ConfigurationError(msg)
        seen.add(row["id"])
        documents.append(ExternalDocument(**{f: row[f] for f in _FIELDS}))
    if not documents:
        msg = f"external corpus {str(path)!r} is empty"
        raise ConfigurationError(msg)
    return tuple(documents)


def load_external_split(directory: Path | None = None) -> ExternalSplit:
    """The external corpus partitioned on its committed manifest."""
    base = directory or default_external_dir()
    documents = load_external(base)
    manifest = load_heldout_manifest(base / "heldout.txt")
    groups = {d.group for d in documents}
    unknown = sorted(manifest.ids - groups)
    if unknown:
        msg = f"external held-out manifest names unknown group(s): {', '.join(unknown)}"
        raise ConfigurationError(msg)
    return ExternalSplit(
        development=tuple(d for d in documents if d.group not in manifest.ids),
        heldout=tuple(d for d in documents if d.group in manifest.ids),
        manifest=manifest,
    )


@dataclass(frozen=True, slots=True)
class ExternalRow:
    label: str
    groups: int
    flagged: Proportion
    """Any finding at all — including ones the template alone produces."""
    caught: Proportion
    """A finding the template alone does not produce: the firewall reacted to
    the attack. This is the recall figure; `flagged` is shown beside it so the
    gap between them is visible rather than silently subtracted."""
    withheld: Proportion


@dataclass(frozen=True, slots=True)
class ExternalReport:
    rows: tuple[ExternalRow, ...]
    """Subset x variant, then each subset's attack types (base form only)."""
    reported_families: dict[str, int]
    """Which detector families fired on the attack and not on its control."""
    template_flagged: int
    """Controls — templates with the attack removed — that produced a finding."""
    deployment: str
    seed: int
    resamples: int


def evaluate_external(
    firewall: Firewall,
    documents: Sequence[ExternalDocument],
    *,
    deployment: Deployment = DEFAULT_DEPLOYMENT,
    seed: int = DEFAULT_SEED,
    resamples: int = DEFAULT_RESAMPLES,
) -> ExternalReport:
    """Screen every document; report detection and withholding per slice."""
    screened = {
        d.id: _screen(firewall, d.text, doc_id=d.id, tools=deployment.catalogue) for d in documents
    }
    control = {
        d.id: _screen(firewall, d.control, doc_id=d.id, tools=deployment.catalogue)
        for d in documents
    }

    def caught(d: ExternalDocument) -> bool:
        return bool(screened[d.id].families - control[d.id].families) or (
            screened[d.id].withheld and not control[d.id].withheld
        )

    rng = random.Random(seed)  # noqa: S311 — reproducibility, not cryptography

    def row(label: str, members: Sequence[ExternalDocument]) -> ExternalRow:
        by_group: dict[str, list[ExternalDocument]] = {}
        for d in members:
            by_group.setdefault(d.group, []).append(d)
        grouped = list(by_group.values())
        return ExternalRow(
            label=label,
            groups=len(grouped),
            flagged=measure_clustered(
                [[screened[d.id].flagged for d in g] for g in grouped],
                rng=rng,
                resamples=resamples,
            ),
            caught=measure_clustered(
                [[caught(d) for d in g] for g in grouped], rng=rng, resamples=resamples
            ),
            withheld=measure_clustered(
                [[screened[d.id].withheld for d in g] for g in grouped],
                rng=rng,
                resamples=resamples,
            ),
        )

    rows: list[ExternalRow] = []
    for subset in SUBSETS:
        for variant in VARIANTS:
            members = [d for d in documents if d.subset == subset and d.variant == variant]
            if members:
                rows.append(row(f"{subset} {variant}", members))
    # The source's attack types, over the base form only. Mixing in the enhanced
    # form would make every type read as "half caught" — which is the prefix
    # being caught, half the time, by construction, and says nothing per type.
    for subset in SUBSETS:
        base = [d for d in documents if d.subset == subset and d.variant == "base"]
        for kind in sorted({d.attack_type for d in base}):
            rows.append(row(f"{subset} base · {kind}", [d for d in base if d.attack_type == kind]))

    families: dict[str, int] = {}
    for d in documents:
        for family in screened[d.id].families - control[d.id].families:
            families[family.value] = families.get(family.value, 0) + 1

    return ExternalReport(
        rows=tuple(rows),
        reported_families=dict(sorted(families.items())),
        template_flagged=sum(1 for d in documents if control[d.id].flagged),
        deployment=deployment.describe(),
        seed=seed,
        resamples=resamples,
    )


# ---------------------------------------------------------------------------
# The baseline: counts, compared, the way ADR 0047 compares the internal corpus
# ---------------------------------------------------------------------------


def default_external_baseline(directory: Path | None = None) -> Path:
    return (directory or default_external_dir()) / "baseline.json"


def baseline_counts(report: ExternalReport) -> dict[str, object]:
    """What `--capture` commits: counts per row, and the configuration they
    were measured under. Counts, not rates, for the reason ADR 0047 gives."""
    return {
        "deployment": report.deployment,
        "rows": {
            row.label: {
                "total": row.caught.total,
                "groups": row.groups,
                "caught": row.caught.successes,
                "withheld": row.withheld.successes,
            }
            for row in report.rows
        },
    }


@dataclass(frozen=True, slots=True)
class ExternalComparison:
    structural: tuple[str, ...]
    regressions: tuple[str, ...]
    improvements: tuple[str, ...]


def compare_external(baseline: dict[str, object], report: ExternalReport) -> ExternalComparison:
    """Fail on fewer attacks caught or withheld; refuse to compare a moved ruler."""
    current = baseline_counts(report)
    structural: list[str] = []
    regressions: list[str] = []
    improvements: list[str] = []
    if baseline.get("deployment") != current["deployment"]:
        structural.append(
            f"deployment changed: {baseline.get('deployment')!r} -> {current['deployment']!r}"
        )
    old_rows = baseline.get("rows")
    new_rows = current["rows"]
    if not isinstance(old_rows, dict) or not isinstance(new_rows, dict):
        return ExternalComparison(("baseline has no rows",), (), ())
    if set(old_rows) != set(new_rows):
        structural.append("the set of rows changed")
    for label in sorted(set(old_rows) & set(new_rows)):
        old, new = old_rows[label], new_rows[label]
        if (old["total"], old["groups"]) != (new["total"], new["groups"]):
            structural.append(f"{label}: corpus size changed")
            continue
        for key in ("caught", "withheld"):
            if new[key] < old[key]:
                regressions.append(f"{label}: {key} {old[key]} -> {new[key]} of {new['total']}")
            elif new[key] > old[key]:
                improvements.append(f"{label}: {key} {old[key]} -> {new[key]} of {new['total']}")
    return ExternalComparison(tuple(structural), tuple(regressions), tuple(improvements))
