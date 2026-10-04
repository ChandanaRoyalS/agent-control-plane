# InjecAgent — imported attack documents

**Source:** [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent), Qiusi Zhan,
Zhixiang Liang, Zidi Ying and Daniel Kang, *InjecAgent: Benchmarking Indirect
Prompt Injections in Tool-Integrated Large Language Model Agents*, Findings of
ACL 2024.

**Licence:** MIT, copyright (c) 2023 Qiusi Zhan. The licence text is in
[`LICENCE`](LICENCE) beside this file and applies to `documents.jsonl`.

**Pinned commit:** `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` (main, 2024-07-02).
Files: `data/test_cases_{dh,ds}_{base,enhanced}.json`.

**What was taken:** for each test case, the simulated tool response (`Tool
Response`) verbatim as `text`, the span the authors inserted into it as
`planted`, and the case's subset, variant and attack type. Nothing else — not the
user instruction, the agent's thought, or the expected achievement.

**Also taken, into `actions.json`:** each instruction's `Attacker Tools`, each
case's `User Tool`, and the tool names from `data/tools.json`, renamed to this
gateway's `upstream__tool` form (`GmailSendEmail` → `gmail__SendEmail`). These
are the actions the attacks aim for; the firewall never sees them (ADR 0063).

**Also taken, into `descriptions.jsonl`:** every toolkit description, tool
summary and parameter description from `data/tools.json`, as a benign
tool-description population for the catalogue screen (ADR 0065).

**What was added:** an `id` (`injecagent/<subset>-<variant>-<index>`, the index
into the source file) and a `group` (`<subset>/<sha256(attacker instruction)[:10]>`).

**How to reproduce:** `uv run python scripts/import_injecagent.py` fetches the
pinned files and rewrites `documents.jsonl` and `heldout.txt`; the output is
byte-identical on every run.

**How it is used:** ADR 0061.
