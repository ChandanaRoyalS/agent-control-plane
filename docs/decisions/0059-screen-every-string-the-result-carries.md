# ADR 0059 — Screen every string the result carries

**Status:** accepted
**Date:** 2026-09-10

## Context

An external review reproduced a bypass in ten minutes. The same payload — a
right-to-left override plus a base64 run decoding to an instruction — was
withheld by an enforcing firewall when it arrived as a text block, and relayed
untouched when it arrived as an embedded resource:

```
{"type":"text",    "text": payload}                 -> refused, 2 triggers
{"type":"resource","resource":{"text": payload}}    -> served,  0 triggers, 0 chars scanned
```

`Firewall.inspect` screened `[block.text for block in result.content]`. An
embedded resource carries its text at `resource.text`, so the screener saw
nothing, the decision layer saw a clean screening, and the fence announced the
block as "1 resource" — a label describing content nobody had inspected.

The comment at that line said an image is bytes and this layer has no opinion
about bytes, which is true and was never the problem. The problem is that the
same line treated *every* field it had no model for as though it were bytes.
The gap was not in the reasoning about images; it was in the scope of "text".

Three further channels were open for the same reason: `structuredContent` (a
top-level result field the model reads), `annotations`, and any content type
added by a future spec revision — which the permissive parse of ADR 0006 turns
into a dictionary entry rather than an error, and therefore into an unscreened
one.

## Decision

**Screen every string in the result, and exclude by name what must be
excluded.** `acp.firewall.content.screenable_strings` walks the parsed result
and returns every string leaf. The exclusion list is two keys — `data` and
`blob`, the base64 payloads of image, audio and binary resource blocks — matched
by key at any depth rather than by the block's declared `type`, because the type
is a string the upstream chose and a security decision must not depend on it.

Everything else is screened, `uri` and `mimeType` included. A resource link's
URI is a place a client may be induced to fetch, and it was previously invisible
to `disallowed_url`.

The walk is bounded by depth (8) and string count (1024), and the screener's
character budget became **the result's rather than each block's**. That last
change is the same bug in a different dimension: a per-block allowance meant a
result with eight blocks bought eight times the screening budget, so the cost of
inspecting a result was a number the upstream picked. Hitting any of the three
bounds sets `truncated`, because a caller that cannot distinguish "nothing
found" from "nothing found in the part I looked at" has a control it does not
have.

## Alternatives considered

**Model every MCP content type explicitly.** Screen `text` on text blocks,
`resource.text` on embedded resources, and so on. Correct today and wrong on the
day the specification adds a type — which is the failure that just happened,
committed to a second time. An allow-list of fields to screen has to be right
about the future; a deny-list of fields to skip only has to be right about
base64.

**Screen `data` too, and accept the false positives.** `encoded_payload` is one
of only two detectors permitted to withhold anything (ADR 0039). It fires on
base64 runs. Screening image payloads would refuse every screenshot any tool
ever returned — a control that refuses honest traffic is a control somebody
switches off (ADR 0038's opening argument), and then it catches nothing at all.

**Keep the per-block character budget.** Rejected because it prices screening in
units the attacker chooses. One budget per result also means the reported
`scanned_chars` is a number about the decision that was made, rather than a sum
over unrelated windows.

**Refuse unmodelled content types outright.** Fails closed, and breaks every
tool that returns something this gateway has not heard of — including tools that
predate the gateway. ADR 0006 chose permissive parsing deliberately; the answer
to "we cannot model it" is to inspect it, not to reject it.

## Consequences

The firewall's coverage no longer shrinks when the specification grows. A new
content type is screened the day it appears, without a code change, and the only
way to add an unscreened channel is to add a key to `BINARY_KEYS` in a diff.

Report-mode finding counts rise, because URIs are now screened and benign
documents link to things. `disallowed_url` is MEDIUM and non-enforceable
(ADR 0039), so this is noise in the numbers rather than refusals — but it means
the benign corpus's measured flag rate is no longer comparable across this
change for results carrying links. The corpus itself is text documents and its
numbers are unaffected.

Ten tests in `tests/unit/firewall/test_content.py` cover this, and six of them
fail against the previous implementation — which is the property that matters,
since all 1,898 existing tests passed against the bypass.

What would make us revisit: a content type whose text field is legitimately
enormous and legitimately not read by the model. There is no such type today,
and if one appears the answer is a third entry in `BINARY_KEYS`, in a diff,
with a reason.
