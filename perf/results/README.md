# Committed overhead results

One JSON file per recorded run of `scripts/measure_overhead.py`, written by
`make overhead-record`: the percentiles for each row, the gateway's switch
settings read from the running container, the commit it ran against, whether
the tree had uncommitted changes, and the machine.

The README's overhead rows and the site's overhead tile are generated from the
newest file here, and a test fails when they disagree with it. Older files stay:
they are the history of what the gateway cost, and a regression is visible as a
diff between two of them.

These numbers are from one machine against mock upstreams that answer in
microseconds. They measure what the gateway adds, not what a deployment costs —
see [`perf/README.md`](../README.md) and ADR 0054.
