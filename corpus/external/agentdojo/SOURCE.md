# AgentDojo — imported environments, goals and attack templates

**Source:** [AgentDojo](https://github.com/ethz-spylab/agentdojo), Edoardo Debenedetti
et al., *AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and
Defenses for LLM Agents* (NeurIPS 2024 Datasets and Benchmarks).

**Pinned release:** the PyPI wheel `agentdojo-0.1.35-py3-none-any.whl`, SHA-256
`364bea4219716b716bf639f504d195943f7f6a5535d312ca41d7098704a2affd`. Files:
`data/suites/{banking,slack,travel,workspace}/` (environments and injection vectors),
`default_suites/*/*/injection_tasks.py` (attacker goals, the latest version of each)
and `attacks/{important_instructions,baseline}_attacks.py` (templates). The wheel is
read as a zip; nothing in it is installed or run.

**Licence:** MIT ([`LICENCE`](LICENCE)). `documents.jsonl` is an adaptation of that
material and is distributed under the same terms.

**What was built:** each object an agent's tool would return (an email, a file, a
review, a web page) rendered as `key: value` lines. Every object with a text field of
60 characters or more is a clean document, with injection vectors at their benign
defaults. Every goal is planted in every injection vector of its suite, once per
template, by the rule in `src/acp/corpus/agentdojo.py`.

**Split:** one goal in three is held out by salted hash; clean objects are split the
same way by their text. AgentDojo's own attack, `important_instructions`, appears only
in the held-out half. The held-out groups are listed in [`heldout.txt`](heldout.txt)
and sealed (ADR 0079).

**How to reproduce:** see `scripts/import_agentdojo.py`; the output is byte-identical.
