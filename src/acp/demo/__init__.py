"""The attack demos.

`agent` is the scripted demo's deterministic parser agent (`scripts/attack_demo.py`).
`model_agent`, `paths` and `record` are the model-driven demo, where a local model decides
every call (ADR 0073, `scripts/record_model_demo.py`).
"""

from acp.demo.agent import MAX_STEPS, Step, instructions

__all__ = ["MAX_STEPS", "Step", "instructions"]
