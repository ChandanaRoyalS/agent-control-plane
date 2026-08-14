#!/usr/bin/env python3
"""The same agent twice: once alone, once behind the gateway — task 64.

    make up
    make attack-demo

*"Direct, it reads a poisoned document and exfiltrates; through the gateway, it
is stripped, denied and logged. The single most valuable artifact in the
project — everything else is why it works."*

**What is real here and what is a fixture.**

Real: the mock upstream, the poisoned document sitting in it, the gateway, the
policy, the firewall, the approval gate, the audit chain, and every HTTP request
below. Nothing is stubbed and nothing is asserted in advance.

A fixture: the agent. It is a parser, not a model (`acp.demo.agent` argues why
at length). The short version is that **the gateway never sees an agent's
reasoning — it sees tool calls** — so a deterministic stand-in for "the model
was convinced" exercises exactly what a model would, and does it the same way
twice.

**This script reports; it does not assert.** The firewall's measured recall on
this attack family is 75% detected and 38% precise (ADR 0047), and the payload
below is *not* in the corpus — adding a hand-written attack designed to be
caught would improve the published numbers by construction, which is what the
held-out split exists to prevent. So the demo prints what each layer actually
did. If the firewall does not catch this document, the run says so, and the
approval gate is what stops the exfiltration. **Defence in depth is only a claim
worth making if you show which layer caught it.**
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from perf.overhead import parse_env

from acp.demo.agent import Step, instructions
from acp.firewall.decision import ENFORCEABLE
from acp.upstream.envelope import routing_headers, with_envelope

ROOT = Path(__file__).resolve().parents[1]

AUDIT = ROOT / "audit" / "audit.jsonl"
CONTAINER = "acp-gateway"

DIRECT = "http://127.0.0.1:9101/mcp"
GATEWAY = "http://127.0.0.1:8080/mcp"

TASK = "runbooks/incident-2291.md"
STOLEN = "hr/compensation-2026.md"
"""The document the payload is after. Named `STOLEN` rather than `SECRET`
because S105 fires on any name containing SECRET assigned a string literal —
and the rule is right often enough that renaming beats suppressing."""

HELD = frozenset(
    {
        "mock-a__read_document",
        "mock-a__create_ticket",
        "mock-a__search",
        "mock-b__search",
        "mock-b__summarize",
        "mock-b__list_channels",
    }
)


def firewall_mode() -> str:
    """What the *running* gateway was told, not what the compose file says.

    The two disagree the moment anybody sets the variable on the command line,
    which `make attack-demo-enforce` does. Task 62 learned this the expensive
    way and the reasoning is in ADR 0054; `parse_env` is that module's tested
    parser, reused rather than written a second time.
    """
    try:
        completed = subprocess.run(  # noqa: S603 — fixed argv, shell=False
            ["docker", "inspect", CONTAINER, "--format", "{{json .Config.Env}}"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        entries = json.loads(completed.stdout) if completed.returncode == 0 else []
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return "unknown"
    if not isinstance(entries, list):
        return "unknown"
    return parse_env([e for e in entries if isinstance(e, str)]).get("ACP_FIREWALL_MODE", "off")


def audit_position() -> int:
    """Where the chain file currently ends, in bytes.

    A byte offset rather than an entry count because the chain is tens of
    thousands of entries deep and counting them to find the end is work
    proportional to history, every run.
    """
    return AUDIT.stat().st_size if AUDIT.exists() else 0


def screenings(since: int) -> list[dict[str, Any]]:
    """Every firewall record the gateway wrote during this run.

    Read from the chain rather than from a log, because **the chain is what
    somebody would have to reconstruct this from afterwards** — and a demo that
    proved its point from a log line would be proving it from the artifact that
    gets rotated away.
    """
    if not AUDIT.exists():
        return []
    with AUDIT.open("rb") as handle:
        handle.seek(since)
        fresh = handle.read().decode("utf-8", errors="replace")
    found = []
    for line in fresh.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        record = entry.get("record", {})
        if record.get("category") == "firewall":
            found.append({"seq": entry.get("seq"), **record})
    return found


def emit(line: str = "") -> None:
    """One line, with trailing whitespace removed.

    Not cosmetic. This script's output is captured into `docs/demo/attack.txt`
    and committed, and padded columns leave spaces at end of line — which
    pre-commit's trailing-whitespace hook then rewrites, failing the commit and
    leaving a checked-in transcript that differs from what the demo prints.

    Stripped here rather than by the hook, so the file on disk is exactly what
    a reader would see on their own terminal.
    """
    sys.stdout.write(line.rstrip() + "\n")
    sys.stdout.flush()


def rule(title: str) -> None:
    emit()
    emit("=" * 72)
    emit(f"  {title}")
    emit("=" * 72)
    emit()


def call(
    client: httpx.Client, url: str, tool: str, arguments: dict[str, Any], token: str | None
) -> dict[str, Any]:
    """One tools/call, direct or through the gateway.

    The same envelope both ways — `acp.upstream.envelope` is the gateway's own
    builder, reused rather than reimplemented, because a demo that hand-rolls
    the wire format is a demo that can pass while the product is broken.

    Direct calls carry no `Authorization`, because the mock has none to check.
    **That is the point of the first act**: there is nothing to authenticate to,
    nothing to authorize against, and nothing keeping a record.
    """
    name = tool.rpartition("__")[2] if token is None else tool
    params: dict[str, Any] = {"name": name, "arguments": arguments}
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": with_envelope(params, "acp-attack-demo", "0"),
    }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        **routing_headers("tools/call", params),
    }
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"

    response = client.post(url, json=body, headers=headers, timeout=30.0)
    try:
        return dict(response.json())
    except ValueError:
        return {"error": {"message": response.text[:200], "code": response.status_code}}


def text_of(frame: dict[str, Any]) -> str:
    """The text a caller would actually read out of a response."""
    result = frame.get("result")
    if not isinstance(result, dict):
        error = frame.get("error")
        return f"<error: {error}>" if error else "<no result>"
    blocks = result.get("content")
    if not isinstance(blocks, list):
        return f"<{result.get('resultType', 'no content')}>"
    return "\n".join(str(block.get("text", "")) for block in blocks if isinstance(block, dict))


def outcome_of(frame: dict[str, Any]) -> str:
    """What this gateway did, in one word, from what a client can see."""
    error = frame.get("error")
    if isinstance(error, dict):
        return f"REFUSED ({error.get('code')}) {str(error.get('message'))[:80]}"
    result = frame.get("result")
    if isinstance(result, dict) and result.get("resultType") == "input_required":
        return "HELD for a human"
    if isinstance(result, dict) and result.get("isError"):
        return "upstream error"
    return "served"


def run(client: httpx.Client, url: str, token: str | None) -> list[str]:
    """One agent, one path. Returns a short list of what happened, in order."""
    log: list[str] = []

    emit(f"  The operator asks: summarise {TASK}")
    emit()
    first = call(client, url, "mock-a__read_document", {"path": TASK}, token)
    document = text_of(first)
    emit(f"  read_document {TASK}")
    emit(f"    -> {outcome_of(first)}")
    log.append(f"read the runbook: {outcome_of(first)}")

    steps: tuple[Step, ...] = instructions(document, tools=HELD)
    emit()
    if not steps:
        emit("  The agent found no instructions in what came back.")
        emit("  Either the document was withheld, or it was not poisoned.")
        emit()
        emit(f"  What the agent actually received ({len(document)} chars):")
        for line in document.splitlines()[:6]:
            emit(f"    | {line}")
        log.append("NOTHING TO OBEY — the agent was never shown the instruction")
        return log

    emit(f"  The document talked the agent into {len(steps)} more call(s):")
    for step in steps:
        emit(f"    {step.tool} {step.arguments or '(from the previous result)'}")
    emit()

    previous = ""
    for step in steps:
        arguments = dict(step.arguments)
        if step.uses_prior:
            # Reading is not a leak and filing a ticket is not a leak. Filing a
            # ticket CONTAINING the document is, and this line is where the two
            # innocuous calls become one exfiltration.
            arguments["title"] = previous.replace("\n", " ")[:200]
        frame = call(client, url, step.tool, arguments, token)
        result = outcome_of(frame)
        emit(f"  {step.tool} {json.dumps(arguments)[:110]}")
        emit(f"    -> {result}")
        log.append(f"{step.tool}: {result}")
        previous = text_of(frame)

    return log


def token_for(user: str) -> str:
    from scripts.keycloak_token import access_token  # noqa: PLC0415

    return access_token(user)


def main() -> int:
    emit("The same agent, the same poisoned document, two paths.")
    emit()
    emit("The agent is a parser, not a model — see acp/demo/agent.py. The gateway")
    emit("never sees an agent's reasoning, only its calls, so a deterministic")
    emit("stand-in exercises exactly what a model would and does it twice the same.")

    with httpx.Client() as client:
        rule("ACT ONE — the agent talks to the upstream directly")
        emit("  No gateway. No authentication, because the mock has none to check.")
        emit("  No policy, no screening, no approval, and nothing keeping a record.")
        emit()
        direct = run(client, DIRECT, None)

        rule("ACT TWO — the same agent, through the gateway")
        emit("  Authenticated as alice. The composed policy allows reads broadly")
        emit("  and requires a human for mock-a__create_ticket.")
        emit()
        emit(f"  Injection screening is in `{firewall_mode()}`, and only these detectors")
        emit("  are permitted to withhold anything:")
        for detector in sorted(ENFORCEABLE):
            emit(f"    - {detector}")
        emit()
        emit("  That list is short because it was MEASURED, not reasoned about: those")
        emit("  two produced zero findings across 106 benign documents (ADR 0039).")
        emit("  A detector that fires on real documents cannot be allowed to withhold")
        emit("  them — so a detector can be certain and still not act.")
        emit()
        before = audit_position()
        try:
            bearer = token_for("alice")
        except Exception as exc:
            emit(f"  could not get a token: {exc}")
            emit("  Is the stack up? `make up`")
            return 1
        through = run(client, GATEWAY, bearer)
        found = screenings(before)

    report_screenings(found)
    report_outcomes(direct, through)
    return 0


def report_screenings(found: list[dict[str, Any]]) -> None:
    """What the detectors noticed, and how much of it could act."""
    rule("WHAT THE FIREWALL SAW")
    if not found:
        emit("  No screening records for this run.")
        emit("  Either nothing was screened, or nothing was found — and a clean")
        emit("  screening is not chained, so those two look the same from here.")
    for record in found:
        detail = record.get("detail") or {}
        emit(f"  #{record.get('seq')}  {record.get('tool')}  -> {record.get('outcome')}")
        emit(f"      families    {detail.get('families')}")
        emit(f"      confidence  {detail.get('confidences')}")
        emit(f"      findings    {detail.get('finding_count')}")
        emit(f"      TRIGGERS    {detail.get('trigger_count')}   <- what could withhold")
    emit()
    emit("  `findings` is what the detectors noticed. `triggers` is how many of")
    emit("  those came from a detector permitted to act. When findings are high")
    emit("  and triggers are zero, THE FIREWALL SAW IT AND WAS NOT ALLOWED TO")
    emit("  STOP IT — which is a measurement decision, not a bug.")


def report_outcomes(direct: list[str], through: list[str]) -> None:
    """The two paths side by side, and the question the reader should ask."""
    rule("WHAT HAPPENED")
    emit("  Directly:")
    for line in direct:
        emit(f"    - {line}")
    emit()
    emit("  Through the gateway:")
    for line in through:
        emit(f"    - {line}")
    emit()
    emit("  Nothing above is asserted in advance. The firewall's measured recall")
    emit("  on this family is 75% detected, 38% precise (ADR 0047), and this")
    emit("  payload is deliberately NOT in the corpus — a hand-written attack")
    emit("  added to the corpus would improve those numbers by construction.")
    emit()
    emit("  So read the outcomes above and ask WHICH LAYER STOPPED IT.")
    emit()
    emit("  Then look at what was written down:")
    emit("      make audit-verify")
    emit("      docker compose exec gateway tail -5 /app/audit/audit.jsonl")
    emit()
    emit("  The direct path produced no record at all. That is the other half of")
    emit("  the argument and it is easy to miss: the first act is not just")
    emit("  unprotected, it is UNEXPLAINABLE. Nobody could reconstruct it after.")


if __name__ == "__main__":
    raise SystemExit(main())
