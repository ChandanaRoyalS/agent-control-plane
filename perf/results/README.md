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

## Concurrent load

`make load-record` runs the locust harness at 20 and 50 concurrent agents for
30 seconds each and writes two things: `load-<date>-<commit>/`, locust's raw
CSVs for each level (`u20_stats.csv`, `u20_stats_history.csv`, failures and
exceptions), and `load-<date>-<commit>.json`, the per-outcome percentiles with
the warm-up window excluded, the switch settings, the commit and the machine.
The README's load rows are generated from the newest summary. A run that
started fewer users than it asked for, or served nothing, is refused rather
than written.
