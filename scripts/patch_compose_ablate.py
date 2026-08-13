#!/usr/bin/env python3
"""Make two more switches settable from the shell, so they can be ablated.

    python3 scripts/patch_compose_ablate.py

`docker-compose.yml` is a drift file, so this is an asserted patch. **Two
anchors, and both are checked before either is written** (rule 2d) — a
half-patched compose file is a gateway that starts under a configuration nobody
chose.

**Why.** `make overhead` said the gateway adds 32.8 ms to a cache-missing call
and **16.0 ms to one served from memory**. `make overhead-ab` attributed about
7 ms of that to the audit `fsync` and roughly half the *tail* to the catalogue
prober — and left about 11 ms unexplained.

Unexplained is the weakest thing a performance number can be, so the remaining
candidates get ablated too. Two of them were pinned rather than interpolated:

- ``ACP_PROVENANCE_FRAMING_ENABLED`` — written as a literal `"true"` by
  `patch_compose_firewall.py`, because at the time there was no reason to vary
  it. There is now.
- ``OTEL_TRACES_EXPORTER`` — a span per request, batched and shipped over OTLP
  to Jaeger. **This one was not in the overhead register at all**, because the
  register was assembled from `GatewaySettings` and tracing is configured by
  OpenTelemetry's standard variables instead. A register built from one source
  of truth misses everything configured by another.

Both keep their current value as the default, so a stack brought up the ordinary
way is unchanged: `${VAR:-current}` is the same configuration with a seam in it.
"""

from __future__ import annotations

import sys
from pathlib import Path

COMPOSE = Path(__file__).resolve().parents[1] / "docker-compose.yml"

# Written by `patch_compose_firewall.py`, so its exact text is known.
FRAMING_BEFORE = '      ACP_PROVENANCE_FRAMING_ENABLED: "true"\n'
FRAMING_AFTER = '      ACP_PROVENANCE_FRAMING_ENABLED: "${ACP_PROVENANCE_FRAMING_ENABLED:-true}"\n'

TRACING_BEFORE = "      OTEL_TRACES_EXPORTER: otlp\n"
TRACING_AFTER = '      OTEL_TRACES_EXPORTER: "${OTEL_TRACES_EXPORTER:-otlp}"\n'

EDITS = ((FRAMING_BEFORE, FRAMING_AFTER), (TRACING_BEFORE, TRACING_AFTER))


def main() -> int:
    print("Making framing and trace export settable from the shell.")

    if not COMPOSE.exists():
        print(f"missing: {COMPOSE}", file=sys.stderr)
        return 1

    text = COMPOSE.read_text(encoding="utf-8")

    if FRAMING_AFTER in text and TRACING_AFTER in text:
        print("  already applied")
        print("done.")
        return 0

    # EVERY anchor checked before ANY is written. A file with one of the two
    # interpolated and the other pinned would ablate one switch and silently
    # not the other, and the table would carry a row that removed nothing.
    missing = [
        before.strip() for before, after in EDITS if before not in text and after not in text
    ]
    if missing:
        joined = "\n    ".join(missing)
        msg = (
            f"docker-compose.yml does not contain the line(s) this patch "
            f"anchors on:\n    {joined}\n"
            f"NOTHING HAS BEEN WRITTEN. Check that scripts/patch_compose_firewall.py "
            f"has been applied."
        )
        raise SystemExit(msg)

    for before, after in EDITS:
        if before in text:
            text = text.replace(before, after, 1)
    COMPOSE.write_text(text, encoding="utf-8")

    print("  applied: ACP_PROVENANCE_FRAMING_ENABLED, OTEL_TRACES_EXPORTER")
    # NOT `docker compose config`: that command RESOLVES interpolation, so
    # `${VAR:-true}` renders as `true` and looks exactly like the pinned line
    # this patch replaced. It cannot show the seam. Read the file instead.
    print("verify with:  grep -E 'FRAMING|TRACES_EXPORTER' docker-compose.yml")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
