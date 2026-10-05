# Evasion corpus v1

Every attack in BIPIA's sealed test split, with its planted instruction disguised one
way: Cyrillic homoglyphs, zero-width characters, spaced letters, leetspeak,
alternating case, base64 split across a line, or a reworded "ignore previous
instructions" prefix. The context is untouched. Transforms are assigned by index;
see `src/acp/corpus/evasion.py`. Built by `scripts/import_bipia.py`, sealed with the
BIPIA test split, and covered by its licence ([`../bipia/LICENCE`](../bipia/LICENCE),
[`../bipia/NOTICE.txt`](../bipia/NOTICE.txt)). This is the evasion corpus the external
review asked for (W9, ADR 0074). Paraphrase and translation are not in v1.
