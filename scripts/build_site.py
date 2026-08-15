#!/usr/bin/env python3
"""Generate `docs/index.html` — the front door, from artifacts the repo owns.

    python scripts/build_site.py            # write docs/index.html
    python scripts/build_site.py --check    # fail if it is out of date

**Generated, never hand-written.** The page's whole claim is that what it shows
happened: the transcript is `docs/demo/attack.txt`, captured from a real run of
`make attack-demo`, and the trace is real links from a real audit chain. A page
edited by hand drifts from those the first time either changes, and a front page
that quietly stops being true is this project's most-repeated failure wearing a
new hat (lesson 67, twice on the README already).

So the page is a build product, `--check` runs in the test suite, and the two
inputs are files in the repository rather than prose in a template.

Three things are asserted before a byte is written, because each would produce a
page that looks fine and says something false:

1. **Every ADR the page links is resolved from disk by number**, so a link
   cannot name a file that does not exist. Lesson 66 -- Markdown and HTML both
   render a dead link exactly as well as a live one.
2. **Every narrative beat's marker is found in the transcript.** The annotations
   are keyed to line numbers computed here; if the demo's wording changes and a
   marker vanishes, the build fails rather than silently dropping the moment the
   page exists to show.
3. **The trace's `prev` links chain.** Each record's `prev` must equal its
   predecessor's `hash`. This does not re-verify the digests -- that is
   `acp audit verify`'s job and it needs the canonical encoding -- but a
   copy-paste that dropped or reordered a line would not survive it.

What is deliberately NOT on the page: any outcome that did not happen. The
gateway's screening detected this attack and was not permitted to act, and the
page says so. A front door showing a firewall winning would contradict
`make attack-demo` on the reader's own machine, which turns the one asset this
project actually has -- everything is checkable -- into evidence of the
opposite.
"""

from __future__ import annotations

import argparse
import itertools
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

ROOT = Path(__file__).resolve().parents[1]

TRANSCRIPT = ROOT / "docs" / "demo" / "attack.txt"
TRACE = ROOT / "docs" / "demo" / "trace.jsonl"
OUTPUT = ROOT / "docs" / "index.html"
DECISIONS = ROOT / "docs" / "decisions"

REPO: Final = "https://github.com/chandanaroyal719-bot/agent-control-plane"
IMAGE: Final = "ghcr.io/chandanaroyal719-bot/agent-control-plane:1.0.0"

RECORD_KEYS: Final = frozenset({"seq", "prev", "hash", "record"})

SHORTEST_PLAUSIBLE_TRANSCRIPT: Final = 20


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


def read_transcript() -> list[str]:
    if not TRANSCRIPT.exists():
        raise SystemExit(f"missing: {TRANSCRIPT}. Run `make attack-demo` and capture it.")
    lines = TRANSCRIPT.read_text(encoding="utf-8").splitlines()
    if len(lines) < SHORTEST_PLAUSIBLE_TRANSCRIPT:
        raise SystemExit(f"{TRANSCRIPT} has {len(lines)} lines, which is not a transcript.")
    return lines


def read_trace() -> list[dict[str, Any]]:
    """Real links from a real chain, with their ordering checked."""
    if not TRACE.exists():
        raise SystemExit(f"missing: {TRACE}")

    records: list[dict[str, Any]] = []
    for number, raw in enumerate(TRACE.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError as error:
            raise SystemExit(f"{TRACE}:{number} is not JSON: {error}") from error
        if not set(entry) >= RECORD_KEYS:
            raise SystemExit(f"{TRACE}:{number} is missing one of {sorted(RECORD_KEYS)}")
        records.append(entry)

    if not records:
        raise SystemExit(f"{TRACE} is empty")

    # The chain, checked as a chain. A pasted log that lost or reordered a line
    # would render perfectly and be a lie about the one property this project
    # sells hardest.
    for earlier, later in itertools.pairwise(records):
        if later["prev"] != earlier["hash"]:
            raise SystemExit(
                f"{TRACE}: entry {later['seq']} does not follow entry {earlier['seq']} "
                f"-- its `prev` is not the previous `hash`. NOTHING HAS BEEN WRITTEN."
            )

    return records


# ---------------------------------------------------------------------------
# ADR links, resolved from disk so they cannot be wrong
# ---------------------------------------------------------------------------


def adr(number: int) -> str:
    matches = sorted(DECISIONS.glob(f"{number:04d}-*.md"))
    if len(matches) != 1:
        raise SystemExit(
            f"expected exactly one ADR numbered {number:04d}, found {len(matches)}. "
            f"NOTHING HAS BEEN WRITTEN."
        )
    return f"{REPO}/blob/main/docs/decisions/{matches[0].name}"


def adr_link(number: int, text: str) -> str:
    return f'<a href="{adr(number)}">{text}</a>'


# ---------------------------------------------------------------------------
# The beats: annotations keyed to lines of the real transcript
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Beat:
    marker: str
    label: str
    tone: str


BEATS: Final = (
    Beat("ACT ONE", "No gateway. No policy, no screening, and nothing keeping a record.", "bad"),
    Beat(
        'mock-a__create_ticket {"title": "# Compensation',
        "The salary table leaves the building, in a ticket title.",
        "bad",
    ),
    Beat("ACT TWO", "The same agent, the same document, through the gateway.", "info"),
    Beat("HELD for a human", "A person is asked, on a listener the agent cannot address.", "good"),
    Beat(
        "TRIGGERS",
        "The detector was certain -- and measured into silence. It saw it and could not act.",
        "warn",
    ),
    Beat(
        "UNEXPLAINABLE",
        "The direct path left no record at all. Nobody could reconstruct it.",
        "bad",
    ),
)


def find_beats(lines: list[str]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for beat in BEATS:
        index = next((i for i, line in enumerate(lines) if beat.marker in line), None)
        if index is None:
            raise SystemExit(
                f"the transcript no longer contains {beat.marker!r}, so the annotation "
                f"keyed to it would silently vanish. NOTHING HAS BEEN WRITTEN."
            )
        found.append({"line": index, "label": beat.label, "tone": beat.tone})
    return sorted(found, key=lambda beat: beat["line"])


# ---------------------------------------------------------------------------
# Content that is prose rather than data
# ---------------------------------------------------------------------------


def measured() -> str:
    rows = (
        ("0 of 106", "benign documents withheld by the injection firewall", 39),
        ("75% / 38%", "recall and precision on the family this attack belongs to", 47),
        ("2.14&times;", "of throughput is what durability costs, measured", 53),
        (
            "12.6&times;",
            "p95 on a path with no disk write &mdash; a defect a load harness found",
            53,
        ),
        (
            "6.7&ndash;7.2&times;",
            "a direct call, on a cache miss, with the switch settings printed",
            54,
        ),
        ("16", "deliberate breakages, caught by the tests written to catch them", 23),
    )
    return "\n".join(
        f'      <a class="tile" href="{adr(number)}">'
        f'<span class="figure">{figure}</span>'
        f'<span class="caption">{caption}</span></a>'
        for figure, caption, number in rows
    )


def subsystems() -> str:
    groups = (
        (
            "Identity",
            "The caller's token reaches exactly one module and never travels onward.",
            [
                "Two identities: who it is for, and which agent did it",
                "A credential minted per call, scoped to one upstream",
                "A sweep, two static alarms and a mutation harness proving it",
            ],
            [15, 19, 23],
        ),
        (
            "Policy",
            "Deny by default, and it is not configurable &mdash; no field, no variable.",
            [
                "A pure function is the whole of the decision logic",
                "Rules reach into arguments, not just tool names",
                "A tool the caller may not call never appears in the catalogue",
            ],
            [25, 26, 31, 29],
        ),
        (
            "Budgets",
            "A per-tool weighted cost against a rate limit and a quota.",
            [
                "A token bucket per principal, checked after authorization",
                "A fixed, clock-aligned window",
                "The one cache that sits inside the policy check",
            ],
            [32, 33, 34, 35],
        ),
        (
            "Firewall",
            "Detect first, decide later, and count the false positives before enforcing anything.",
            [
                "106 benign documents, and the two detectors that survived",
                "Retrieved text fenced in a boundary the document cannot forge",
                "A refusal that never quotes what it withheld",
            ],
            [36, 37, 38, 39, 47],
        ),
        (
            "Approvals",
            "An agent cannot approve its own call because it cannot address\n"
            "            the thing that approves calls.",
            [
                "An approval is granted to a call, fingerprinted, not to a token",
                "Answered on the admin listener, and that placement is the control",
            ],
            [48, 49],
        ),
        (
            "Audit",
            "A call this gateway cannot record does not happen.",
            [
                "A hash chain, verified against an anchor the gateway cannot reach",
                "What it does not detect is asserted as a passing test",
                "A tenant comes from the registration that verified the token",
            ],
            [50, 51],
        ),
        (
            "Performance",
            "Latency per outcome, because an average over four populations\n"
            "            describes no request that was made.",
            [
                "A load harness that found fsync on the event loop",
                "An overhead number printed beside its switch settings",
                "A second run that bounded the harness's own error",
            ],
            [52, 53, 54],
        ),
    )
    blocks = []
    for name, line, bullets, numbers in groups:
        items = "".join(f"<li>{bullet}</li>" for bullet in bullets)
        links = " ".join(adr_link(number, f"{number:04d}") for number in numbers)
        blocks.append(
            f'      <article class="card">\n'
            f"        <h3>{name}</h3>\n"
            f'        <p class="claim">{line}</p>\n'
            f"        <ul>{items}</ul>\n"
            f'        <p class="adrs">{links}</p>\n'
            f"      </article>"
        )
    return "\n".join(blocks)


LIMITS: Final = (
    "It does not stop prompt injection. It measures how much it catches and\n"
    "    publishes the families it misses.",
    "It is not a proxy for arbitrary HTTP. One MCP specification revision only;\n"
    "    an earlier one is refused by name.",
    "One identity provider per tenant. Many tenants behind one issuer is a declared non-goal.",
    "The audit chain does not detect tail truncation. An external anchor does,\n"
    "    and that limit is asserted as a passing test.",
    "No audit log rotation. The chain file grows without bound.",
    "The result cache and the credential cache are in-process. Two replicas do not share them.",
)


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------

TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent Control Plane &mdash; a security boundary for AI agents</title>
<meta name="description" content="A policy-enforcing, injection-screening MCP
 gateway. A real captured run in which the firewall detected an attack at high
 confidence and was not permitted to stop it.">
<meta property="og:title" content="Agent Control Plane">
<meta property="og:description" content="What happens when an AI agent reads a
 poisoned document. A real captured run, not a mock-up.">
<style>
:root{
  --bg:#0b0d10; --panel:#111419; --panel2:#0e1116; --line:#222932;
  --fg:#c9d1d9; --dim:#7d8590; --faint:#4d545c;
  --ok:#3fb950; --warn:#d29922; --bad:#f85149; --link:#58a6ff;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--fg);font-family:var(--sans);
  font-size:15px;line-height:1.6;-webkit-font-smoothing:antialiased}
a{color:var(--link);text-decoration:none}
a:hover{text-decoration:underline}
main{max-width:1080px;margin:0 auto;padding:0 20px 80px}
section{padding:44px 0;border-top:1px solid var(--line);scroll-margin-top:56px}
section:first-of-type{border-top:none}
h2{font-size:13px;letter-spacing:.14em;text-transform:uppercase;color:var(--dim);
  margin:0 0 18px;font-weight:600}
h3{font-size:15px;margin:0 0 6px}
p{margin:0 0 12px}
.bar{border-bottom:1px solid var(--line);background:var(--panel2);position:sticky;top:0;z-index:20}
.bar .inner{max-width:1080px;margin:0 auto;padding:11px 20px;display:flex;
  align-items:center;gap:14px;flex-wrap:wrap}
.brand{font-family:var(--mono);font-size:13px;letter-spacing:.16em;text-transform:uppercase}
.dot{width:7px;height:7px;border-radius:50%;background:var(--ok);display:inline-block;
  margin-right:7px;vertical-align:middle}
.bar nav{margin-left:auto;display:flex;gap:16px;font-size:13px;font-family:var(--mono)}
.lede h1{font-size:30px;line-height:1.25;margin:26px 0 14px;font-weight:600;max-width:26em}
.lede .sub{color:var(--dim);max-width:44em;font-size:16px}
.pill{display:inline-block;font-family:var(--mono);font-size:11px;letter-spacing:.1em;
  text-transform:uppercase;color:var(--dim);border:1px solid var(--line);
  border-radius:2px;padding:3px 8px;margin-right:8px}
.controls{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:18px 0 14px}
button{font-family:var(--mono);font-size:13px;background:var(--panel);color:var(--fg);
  border:1px solid var(--line);border-radius:3px;padding:9px 16px;cursor:pointer}
button:hover{border-color:#39414d}
button.primary{border-color:var(--ok);color:var(--ok)}
button.primary:hover{background:rgba(63,185,80,.08)}
input[type=range]{flex:1;min-width:180px;height:3px;-webkit-appearance:none;appearance:none;
  background:var(--line);border-radius:2px;outline:none}
input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:11px;height:11px;
  border-radius:50%;background:var(--dim);cursor:pointer}
input[type=range]::-moz-range-thumb{width:11px;height:11px;border:none;border-radius:50%;
  background:var(--dim);cursor:pointer}
.termwrap{display:grid;grid-template-columns:minmax(0,1fr) 260px;gap:16px}
@media(max-width:820px){.termwrap{grid-template-columns:1fr}}
.term{background:var(--panel2);border:1px solid var(--line);border-radius:4px;
  height:460px;overflow:auto;padding:14px 16px;font-family:var(--mono);
  font-size:12.5px;line-height:1.55;white-space:pre;color:#b8c1cb}
.term .hd{color:var(--faint)}
.term .ok{color:var(--ok)}
.term .held{color:var(--warn);font-weight:600}
.term .alarm{color:var(--bad);font-weight:600}
.term .em{color:#e6edf3;font-weight:600}
.rail{display:flex;flex-direction:column;gap:8px}
.beat{border:1px solid var(--line);border-left-width:3px;border-radius:3px;
  padding:9px 11px;font-size:12.5px;color:var(--dim);background:var(--panel);
  opacity:.25;transition:opacity .25s}
.beat.on{opacity:1;color:var(--fg)}
.beat.bad{border-left-color:var(--bad)}
.beat.warn{border-left-color:var(--warn)}
.beat.good{border-left-color:var(--ok)}
.beat.info{border-left-color:var(--faint)}
.note{color:var(--dim);font-size:13px;margin-top:12px}
.finding{border:1px solid var(--line);border-left:3px solid var(--warn);
  background:var(--panel);border-radius:3px;padding:16px 18px;margin-top:6px}
.finding p:last-child{margin-bottom:0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px}
.tile{display:block;border:1px solid var(--line);border-radius:3px;padding:15px 16px;
  background:var(--panel);color:var(--fg)}
.tile:hover{border-color:#39414d;text-decoration:none}
.tile .figure{display:block;font-family:var(--mono);font-size:23px;color:#e6edf3;margin-bottom:5px}
.tile .caption{display:block;font-size:12.5px;color:var(--dim);line-height:1.45}
.card{border:1px solid var(--line);border-radius:3px;padding:15px 16px;background:var(--panel)}
.card .claim{color:var(--dim);font-size:13px}
.card ul{margin:8px 0 10px;padding-left:17px;font-size:13px;color:var(--fg)}
.card li{margin-bottom:3px}
.card .adrs{margin:0;font-family:var(--mono);font-size:11.5px}
.deck{color:var(--dim);max-width:46em;font-size:16px}
.chain{border:1px solid var(--line);border-radius:4px;overflow:hidden}
.rec{display:grid;grid-template-columns:44px 116px minmax(0,1fr) 108px;gap:12px;
  padding:11px 14px;border-top:1px solid var(--line);font-family:var(--mono);font-size:12px;
  align-items:baseline}
.rec:first-child{border-top:none}
.rec.held{background:rgba(210,153,34,.06)}
.seq{color:var(--faint)}
.cat{color:var(--dim);text-transform:uppercase;letter-spacing:.06em;font-size:10.5px}
.ev{color:#e6edf3;word-break:break-all}
.ev .meta{display:block;color:var(--dim);font-size:11px;margin-top:3px}
.out{text-align:right;letter-spacing:.06em;font-size:11px;text-transform:uppercase}
.out.allowed,.out.completed{color:var(--ok)}
.out.held{color:var(--warn)}
.hashes{font-family:var(--mono);font-size:11px;color:var(--faint);
  padding:10px 14px;border-top:1px solid var(--line);word-break:break-all}
ul.limits{list-style:none;padding:0;margin:0;display:grid;
  grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:10px}
ul.limits li{border:1px solid var(--line);border-left:3px solid var(--faint);
  border-radius:3px;padding:12px 14px;font-size:13.5px;color:var(--fg);background:var(--panel)}
pre.cmd{font-family:var(--mono);font-size:12.5px;background:var(--panel2);
  border:1px solid var(--line);border-radius:3px;padding:12px 14px;overflow:auto;color:#b8c1cb}
footer{border-top:1px solid var(--line);color:var(--dim);font-size:13px;
  max-width:1080px;margin:0 auto;padding:22px 20px 60px}
</style>
</head>
<body>

<header class="bar"><div class="inner">
  <span class="brand"><span class="dot"></span>Agent Control Plane</span>
  <nav>
    <a href="#replay">Replay</a>
    <a href="#trace">Trace</a>
    <a href="#measured">Measured</a>
    <a href="#limits">Limits</a>
    <a href="%%REPO%%">Repository</a>
  </nav>
</div></header>

<main>

<section class="lede">
  <div>
    <span class="pill">MCP gateway</span>
    <span class="pill">v1.0.0</span>
    <span class="pill">1,893 tests</span>
  </div>
  <h1>An AI agent reads a document. The document tells it to do something else.</h1>
  <p class="deck">This is the security boundary that sits in between &mdash; it decides what an
  agent may do, screens what comes back for injected instructions, and writes down every
  decision in a chain you can verify. Below is a real captured run, not a mock-up.
  It does not end the way a demo usually ends.</p>
</section>

<section id="replay">
  <h2>The attack, replayed</h2>
  <div class="controls">
    <button id="play" class="primary">&#9654;&nbsp; Replay the attack</button>
    <button id="skip">Skip to the end</button>
    <input id="scrub" type="range" min="0" max="100" value="0" aria-label="Position">
  </div>
  <div class="termwrap">
    <div class="term" id="term"></div>
    <div class="rail" id="rail"></div>
  </div>
  <p class="note">Verbatim output of <code>make attack-demo</code>, captured to
  <a href="%%REPO%%/blob/main/docs/demo/attack.txt">docs/demo/attack.txt</a> and rendered here
  by a build step &mdash; a test fails if this page and that file disagree.</p>
</section>

<section id="what">
  <h2>What just happened</h2>
  <div class="finding">
    <p><strong>The firewall detected it, at high confidence, and was not allowed
    to stop it.</strong>
    Three findings, zero triggers. Only two detectors are permitted to withhold a result, and the
    list is short because it was measured: those two produced zero findings across 106 ordinary
    documents. The detector that caught this one flags roughly one benign document in five, and
    a control that eats real documents is a control somebody switches off.</p>
    <p>So three layers looked at this attack. <strong>Screening saw it and was measured into
    silence. Provenance framing labelled it and travelled with the payload</strong> &mdash; the
    agent carried the fenced text forward, so the fence did not stop the leak.
    <strong>A person, asked a direct question on a channel the agent cannot
    reach, stopped it.</strong></p>
    <p>That is a better argument for defence in depth than a run where the first layer wins, and
    it is only available because %%ADR57%% reports what happened instead of asserting it.
    And the first act is not merely unprotected &mdash; it is <em>unexplainable</em>. It left no
    record at all.</p>
  </div>
</section>

<section id="trace">
  <h2>What was written down</h2>
  <p class="deck">Real links from a real chain. Each entry
  carries the hash of the one before it, so a modified, spliced or reordered record breaks
  verification at exactly that point &mdash; and the fourth entry below is the moment the ticket
  was held for a human.</p>
  <div class="chain">
%%TRACE%%
    <div class="hashes" id="hashes"></div>
  </div>
  <p class="note">What this does <em>not</em> detect is truncation of the tail; an external
  anchor does, and that limit is asserted as a passing test. %%ADR50%%</p>
</section>

<section id="measured">
  <h2>Measured, not asserted</h2>
  <div class="grid">
%%MEASURED%%
  </div>
  <p class="note">Every figure links to the decision record that produced it, including the two
  that record a prediction the author got wrong.</p>
</section>

<section id="subsystems">
  <h2>What is in the path</h2>
  <div class="grid">
%%SUBSYSTEMS%%
  </div>
</section>

<section id="limits">
  <h2>What it does not do</h2>
  <ul class="limits">
%%LIMITS%%
  </ul>
</section>

<section id="run">
  <h2>Run it yourself</h2>
  <pre class="cmd">git clone %%REPO%%.git
cd agent-control-plane
docker compose up -d --wait
make attack-demo        # the transcript above, on your machine
make audit-verify       # walk the chain it just wrote</pre>
  <p class="note">Or pull the published image, pinned:
  <code>docker pull %%IMAGE%%</code></p>
</section>

</main>

<footer>
  <a href="%%REPO%%">Repository</a> &middot;
  <a href="%%REPO%%/blob/main/docs/decisions/README.md">58 architecture decisions</a> &middot;
  <a href="%%REPO%%/blob/main/docs/THREAT_MODEL.md">Threat model</a> &middot;
  <a href="%%REPO%%/releases/tag/v1.0.0">v1.0.0</a>
  <p style="margin-top:10px;color:var(--faint)">This page is generated from files in the
  repository. Nothing on it is a mock-up.</p>
</footer>

<script id="site-data" type="application/json">%%DATA%%</script>
<script>
(function(){
  "use strict";
  var data = JSON.parse(document.getElementById("site-data").textContent);
  var lines = data.transcript.split("\\n");
  var beats = data.beats;

  var term = document.getElementById("term");
  var rail = document.getElementById("rail");
  var play = document.getElementById("play");
  var skip = document.getElementById("skip");
  var scrub = document.getElementById("scrub");

  beats.forEach(function(b, i){
    var el = document.createElement("div");
    el.className = "beat " + b.tone;
    el.id = "beat-" + i;
    el.textContent = b.label;
    rail.appendChild(el);
  });

  function classify(line){
    if (line.indexOf("====") !== -1) return "hd";
    if (line.indexOf("HELD for a human") !== -1) return "held";
    if (line.indexOf("TRIGGERS") !== -1) return "alarm";
    if (line.indexOf("UNEXPLAINABLE") !== -1) return "alarm";
    if (line.indexOf("-> served") !== -1) return "ok";
    if (line.indexOf("ACT ONE") !== -1 || line.indexOf("ACT TWO") !== -1) return "em";
    if (line.indexOf("WHAT THE FIREWALL SAW") !== -1) return "em";
    return "";
  }

  function renderTo(n){
    var html = "";
    for (var i = 0; i < n; i++){
      var cls = classify(lines[i]);
      var text = lines[i]
        .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
      html += cls ? '<span class="' + cls + '">' + text + "</span>\\n" : text + "\\n";
    }
    term.innerHTML = html;
    for (var j = 0; j < beats.length; j++){
      document.getElementById("beat-" + j)
        .classList.toggle("on", n > beats[j].line);
    }
    scrub.value = String(Math.round((n / lines.length) * 100));
  }

  var shown = 0, timer = null;

  function stop(){
    if (timer){ clearTimeout(timer); timer = null; }
    play.textContent = "\\u25B6  Replay the attack";
  }

  function step(){
    if (shown >= lines.length){ stop(); return; }
    shown++;
    renderTo(shown);
    term.scrollTop = term.scrollHeight;
    var line = lines[shown - 1] || "";
    var wait = 55;
    if (line.indexOf("====") !== -1) wait = 240;
    if (line.trim() === "") wait = 20;
    for (var i = 0; i < beats.length; i++){
      if (beats[i].line === shown - 1) { wait = 700; }
    }
    timer = setTimeout(step, wait);
  }

  play.addEventListener("click", function(){
    if (timer){ stop(); return; }
    if (shown >= lines.length) shown = 0;
    play.textContent = "Pause";
    step();
  });

  skip.addEventListener("click", function(){
    stop(); shown = lines.length; renderTo(shown); term.scrollTop = term.scrollHeight;
  });

  scrub.addEventListener("input", function(){
    stop();
    shown = Math.round((Number(scrub.value) / 100) * lines.length);
    renderTo(shown);
    term.scrollTop = term.scrollHeight;
  });

  renderTo(0);

  // Autoplay once, when the terminal is actually on screen. A visitor who does
  // not click still sees the thing the page exists to show; a visitor who
  // scrolls past has not had anything animate off-screen at them.
  if ("IntersectionObserver" in window){
    var started = false;
    var watcher = new IntersectionObserver(function(entries){
      entries.forEach(function(entry){
        if (entry.isIntersecting && !started){
          started = true;
          watcher.disconnect();
          play.textContent = "Pause";
          step();
        }
      });
    }, {threshold: 0.35});
    watcher.observe(term);
  }

  var first = data.trace[0], last = data.trace[data.trace.length - 1];
  document.getElementById("hashes").textContent =
    "chain head " + last.hash.slice(0, 24) + "\\u2026   \\u00b7   " +
    data.trace.length + " links   \\u00b7   genesis prev " + first.prev.slice(0, 16) + "\\u2026";
})();
</script>
</body>
</html>
"""


def render_trace(records: list[dict[str, Any]]) -> str:
    rows = []
    for entry in records:
        record = entry["record"]
        outcome = str(record.get("outcome") or "")
        target = record.get("tool") or record.get("upstream") or "&mdash;"
        rule = record.get("rule")
        meta = f"<span class='meta'>{target}"
        if rule:
            meta += f" &middot; rule <em>{rule}</em>"
        meta += "</span>"
        held = " held" if outcome == "held" else ""
        rows.append(
            f'    <div class="rec{held}">'
            f'<span class="seq">{entry["seq"]:02d}</span>'
            f'<span class="cat">{record["category"]}</span>'
            f'<span class="ev">{record["event"]}{meta}</span>'
            f'<span class="out {outcome}">{outcome}</span>'
            f"</div>"
        )
    return "\n".join(rows)


def build() -> str:
    lines = read_transcript()
    records = read_trace()

    data = json.dumps(
        {
            "transcript": "\n".join(lines),
            "beats": find_beats(lines),
            "trace": [{"prev": e["prev"], "hash": e["hash"]} for e in records],
        },
        separators=(",", ":"),
    ).replace("</", "<\\/")

    limits = "\n".join(f"    <li>{item}</li>" for item in LIMITS)

    page = TEMPLATE
    page = page.replace("%%REPO%%", REPO)
    page = page.replace("%%IMAGE%%", IMAGE)
    page = page.replace("%%ADR57%%", adr_link(57, "the demo"))
    page = page.replace("%%ADR50%%", adr_link(50, "ADR 0050"))
    page = page.replace("%%TRACE%%", render_trace(records))
    page = page.replace("%%MEASURED%%", measured())
    page = page.replace("%%SUBSYSTEMS%%", subsystems())
    page = page.replace("%%LIMITS%%", limits)
    page = page.replace("%%DATA%%", data)

    if "%%" in page:
        leftover = page[page.index("%%") : page.index("%%") + 40]
        raise SystemExit(f"a placeholder was not filled: {leftover!r}. NOTHING HAS BEEN WRITTEN.")

    return page


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate docs/index.html.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if docs/index.html is out of date rather than writing it",
    )
    args = parser.parse_args(argv)

    page = build()

    if args.check:
        if not OUTPUT.exists():
            print(f"{OUTPUT.relative_to(ROOT)} does not exist. Run: make site", file=sys.stderr)
            return 1
        if OUTPUT.read_text(encoding="utf-8") != page:
            print(
                f"{OUTPUT.relative_to(ROOT)} is out of date with its inputs. Run: make site",
                file=sys.stderr,
            )
            return 1
        print("The site is up to date with the transcript and the chain.")
        return 0

    OUTPUT.write_text(page, encoding="utf-8")
    nojekyll = OUTPUT.parent / ".nojekyll"
    nojekyll.touch()
    print(f"wrote {OUTPUT.relative_to(ROOT)}  ({len(page):,} bytes)")
    print(f"      {len(read_transcript())} transcript lines, {len(read_trace())} chain links")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
