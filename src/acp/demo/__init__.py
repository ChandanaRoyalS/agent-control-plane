"""The scripted attack demo — task 64.

`agent` is the credulous half: a deterministic stand-in for a model that acts on
instructions it retrieved. The driver is `scripts/attack_demo.py`.
"""

from acp.demo.agent import MAX_STEPS, Step, instructions

__all__ = ["MAX_STEPS", "Step", "instructions"]
