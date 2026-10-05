"""The attack demos.

`agent` is the credulous half of the scripted demo: a deterministic stand-in
for a model that acts on instructions it retrieved, driven by
`scripts/attack_demo.py`. `model_agent`, `paths` and `record` are the
model-driven demo (ADR 0073): a local model decides every call, directly and
through the gateway, driven by `scripts/record_model_demo.py`.
"""

from acp.demo.agent import MAX_STEPS, Step, instructions

__all__ = ["MAX_STEPS", "Step", "instructions"]
