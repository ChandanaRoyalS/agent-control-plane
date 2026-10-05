# BIPIA — imported contexts and attack instructions

**Source:** [BIPIA](https://github.com/microsoft/BIPIA), Jingwei Yi et al., *Benchmarking
and Defending Against Indirect Prompt Injection Attacks on Large Language Models*
(2023).

**Pinned commit:** `a004b69ec0dd446e0afd461d98cb5e96e120a5d0` (2024-04-15).
Files: `benchmark/{email,table,code}/{train,test}.jsonl` and
`benchmark/{text,code}_attack_{train,test}.json`.

**Licence:** the repository is MIT ([`LICENCE`](LICENCE)). Its contexts incorporate
the WikiTableQuestions dataset and Stack Exchange content (CC BY-SA 4.0) and invoice
data from OpenAI Evals; their notices are reproduced verbatim in
[`NOTICE.txt`](NOTICE.txt). `documents.jsonl` is an adaptation of that material and is
distributed under the same terms.

**What was built:** every context once as a clean document, and every attack
instruction planted in four contexts (text attacks into emails and tables, code
attacks into Stack Overflow answers) at the start, middle or end, by the fixed rule
in `src/acp/corpus/bipia.py`. Train tables beyond the first 100 are clean only.
Eleven train contexts that BIPIA repeats in its test split were dropped from train.

**Split:** BIPIA's own. Its test split is sealed in [`heldout.txt`](heldout.txt)
(ADR 0074).

**How to reproduce:** see `scripts/import_bipia.py`; the output is byte-identical.
