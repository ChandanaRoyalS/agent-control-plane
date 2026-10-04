# Poisoned tool descriptions

Eight `tools/list` entries with an attack in the description or a parameter
description, one per detector family where the surface allows it, each with the
outcome the catalogue screen is expected to produce (`withheld`, `detected`,
`undetected`). Written by the detectors' author, so a behaviour check and not a
generalisation estimate — the benign half of the measurement is the 1,096
descriptions nobody here wrote in `corpus/external/injecagent/descriptions.jsonl`.

`tests/integration/test_description_corpus.py` fails when any outcome changes in
either direction. ADR 0065 records the result.
