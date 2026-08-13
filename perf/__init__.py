"""Load and latency measurement (Phase 8).

A package rather than loose scripts so `perf.scenarios` resolves the same way
for pytest, mypy and Locust — three tools with three import mechanisms, and a
module that only two of them can find is one that gets checked by two of them.
"""
