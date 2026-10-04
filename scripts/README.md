# scripts/

Operational and verification scripts. None is part of the shipped package
(see `.dockerignore`); each is reachable through a `make` target or a CI step.

| script | run via | what it does |
|---|---|---|
| `evaluate.py` | `make eval`, CI (`--check`) | Scores the firewall against the committed corpus, false positives first; `--check` fails if any count regressed against `corpus/eval-baseline.json`. |
| `corpus_stats.py` | `make corpus` | Describes the benign corpus and what each detector does to it. |
| `mutate_no_passthrough.py` | `make prove-passthrough`, CI | Breaks the no-passthrough invariant three ways and requires the suite to catch each. |
| `mutate_result_cache.py` | `make prove-cache`, CI | Drops each field from the result-cache key and requires the isolation test to fail. |
| `mutate_refusal.py` | `make prove-refusal`, CI | Breaks the firewall refusal six ways and requires the tests to notice. |
| `prove_predispatch.py` | `make prove-predispatch`, CI | Searches sampled policies for a call the pre-dispatch check refuses and the evaluator would allow. |
| `compose_smoke.py` | `make smoke`, CI | Asserts the composed stack works from outside every container. |
| `identity_smoke.py` | `make identity-smoke`, CI | Asserts the identity stack against the real Keycloak in the compose stack. |
| `keycloak_token.py` | `make token` | Obtains an access token from the composed Keycloak (also a library). |
| `attack_demo.py` | `make attack-demo` | Runs the same credulous agent twice against a poisoned document: directly, then through the gateway. |
| `measure_overhead.py` | `make overhead` | Measures what the gateway adds over a direct upstream call, printing the switch settings it ran under. |
| `ablate_overhead.py` | `make overhead-ablate` | Itemises the gateway's fixed cost by switching one control off at a time. |
| `probe_resource_indicator.py` | `make probe-resource` | Measures what Keycloak does with RFC 8707 `resource` (ADR 0020). |
| `probe_cimd.py` | `make probe-cimd` | Measures whether Keycloak accepts a Client ID Metadata Document (ADR 0024). |
| `capture_surface.py` | `make surface`, release | Compares the public surface against `docs/surface.json` (ADR 0058). |
| `build_site.py` | `make site`, CI | Generates `docs/index.html` from committed artifacts; `--check` fails if it is stale. |
| `release_notes.py` | release workflow | Prints one version's section of `CHANGELOG.md`. |
