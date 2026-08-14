# ADR 0058 — A version is a promise about a surface, so name the surface

**Status:** accepted
**Date:** 2026-08-14

## Context

Task 67: *"v1.0.0 with a real changelog, semantic versioning, and a published
container image."*

Semantic versioning is a rule about breaking changes, and "breaking change" is
undefined until somebody says **breaking for whom**. The specification's own
answer is "the public API", which is written for libraries and is exactly the
wrong noun here.

Nobody imports `acp`. There is no downstream package. What a user of this
project has is a container, an environment, a command line and a log file — and
every one of those can break without a single Python signature changing.

So a project that adopts semver without naming its surface has adopted a
version number and not a contract. It will bump the minor for a refactor nobody
can observe and bump the patch for a renamed environment variable, and both
decisions will feel principled at the time.

## Decision

### 1. The surface is four things, and they are the four a deployment touches

| | why it is in |
|---|---|
| every `ACP_*` variable, its type and its **default** | renaming one gives a gateway that starts with the old behaviour and reports nothing |
| every CLI command and option | they are in somebody's Makefile and somebody's runbook |
| the audit record's version, categories, outcomes and fields | a chain written by 1.0 has to still verify under 1.1 |
| the MCP specification revision | ADR 0001 pins it, and a client speaks it |

The default is in the list on purpose and is the least obvious entry.
`ACP_AUDIT_FSYNC` silently changing from `true` to `false` breaks nothing that
any test can see: every suite passes, every request succeeds, and the durability
guarantee the audit chain rests on is gone. **This project's most repeated bug
is valid input, no error, silently different behaviour** (lesson 46, six
instances). A default is where that bug lives.

### 2. What is deliberately outside it

- **The Python API.** Not because it is unimportant internally, but because a
  promise nobody is relying on is a promise that costs to keep and buys nothing.
- **Policy file semantics beyond the schema.** The schema is checked; whether a
  given rule set produces a given decision is what `acp policy simulate` is for
  (ADR 0045), which is a stronger tool than a version number.
- **The wire protocol.** Not because it does not matter — because it is pinned
  to one specification revision and verified by a conformance suite against a
  server this project did not write (ADR 0008). **A snapshot would be a weaker
  guarantee than the one already in place**, and adding it would suggest
  otherwise.
- **`perf/` and `scripts/`.** Development tools. Their output is quoted in ADRs
  and their interfaces are not promised.

### 3. The surface is a file, and a test fails when it changes

`docs/surface.json` is captured from the running code by
`scripts/capture_surface.py --capture`, exactly as `corpus/eval-baseline.json`
is captured by `scripts/evaluate.py --capture`. **A snapshot a person writes by
hand is a wish; a snapshot a machine writes is a record.**

The test does **not** decide whether a change is breaking. It cannot: that
judgement needs to know whether anybody depends on the thing, which is not in
the repository. What it does is make the change *impossible to miss* — a line
leaving `docs/surface.json` is a line in a pull request diff, and a reviewer has
to look at it before the merge.

That is the whole mechanism, and it is deliberately small. The failure being
prevented is not "somebody made a bad call about the version number." It is
**nobody making a call at all**, because nobody knew there was one to make.

Accepting a change is one command and prints the rule it implies:

```
a variable, command or audit field REMOVED or RENAMED -> major
a default CHANGED                                     -> major
anything ADDED                                        -> minor
```

### 4. The snapshot check is broken on purpose, six ways

A snapshot test that has never been seen to fail is a claim about whoever wrote
it (ADR 0023). This project has four mutation harnesses for exactly that reason,
and the sixth would have been a fifth — except that `acp.surface` is **pure**,
so the mutations are dictionary edits inside ordinary tests rather than a script
that rewrites the source and runs pytest.

`tests/unit/test_surface.py` removes a setting, adds one, changes
`ACP_AUDIT_FSYNC`'s default, renames a command, empties a command's options and
deletes an audit field — and asserts the comparison names each. Plus the one
that matters most for a snapshot of any kind: **an empty snapshot must not
compare clean** (lesson 65).

### 5. The version lives in two files, and a test makes them agree

`pyproject.toml` needs it for packaging; `acp.__version__` needs to be
importable. **Two sources of truth for one fact is a disagreement waiting for a
release** — a wheel whose metadata says 1.1.0 and whose `--version` says 1.0.0,
noticed only by whoever is trying to reproduce a bug.

Single-sourcing through `importlib.metadata` was the alternative and was
rejected: it reads the *installed* distribution, so a developer running from a
checkout gets whatever was last `pip install`ed, which is the same failure with
a longer path to it. A test is two lines and cannot be wrong about which file it
read.

### 6. The changelog is written by hand, and parsed

`git log` records units of *work*; a release note describes units of *change*.
"fix review comments" is in the history and belongs nowhere near a release. So
`CHANGELOG.md` is written by a person — which means it can be stale, wrong, or
missing the version being tagged.

So it is parsed (`acp.changelog`, pure, tested) and checked: the current version
has a section, that section has a date and a non-empty body, versions descend,
`[Unreleased]` is first if it exists, and nothing appears twice. The release
workflow takes the published notes **from that file**, so a release cannot be
published with notes nobody wrote.

### 7. Every assertion runs before anything is pushed

`release.yml` re-verifies the tagged commit: the tag matches
`acp.__version__`, the changelog describes it, the surface matches its snapshot,
lint and types and the full suite pass, and all four mutation harnesses still
catch what they are meant to catch. Only then does it build.

Then it builds, and asserts **on the built image** before logging in to any
registry:

- `acp.mocks` is absent. `WITH_MOCKS` is a build argument, and **a build
  argument with a typo in its name is silently ignored** — the build succeeds
  and ships two servers with deliberately controllable failure modes inside an
  artifact whose entire purpose is to be a security boundary.
- the container runs as uid 10001.
- the image reports the version it is tagged with. The tag, the code and the
  artifact, agreeing — two of the three were checked before the build, and this
  is the third.

The registry login is the **last** step before the push, after every assertion.
A login earlier would leave a session open to a public registry for the rest of
a job that has already decided to fail.

### 8. `latest` is published, and the README does not use it

`latest` is what somebody gets when they forget to pin, so it exists — refusing
to publish it does not make anybody pin, it makes them write a worse
`docker run`. Every example in this repository names a version.

## Consequences

- `src/acp/surface.py` — pure, 4 sections, no file access, takes the parser as
  a parameter. `src/acp/changelog.py` — pure, one regular expression.
- `docs/surface.json` — 56 settings, every command path, the audit record.
- `scripts/capture_surface.py`, `scripts/release_notes.py` — the wiring.
- `.github/workflows/release.yml` — on `v*` only.
- `make surface`, `make surface-capture`, `make release-notes`.
- 48 tests.

## The honest cuts

**One architecture, `linux/amd64`.** A multi-architecture manifest cannot be
loaded into the local daemon, and the three assertions above run by *executing
the image*. Publishing an `arm64` variant would mean either dropping those
checks or building twice and reasoning about which one was tested — and an
untested `arm64` image is worse than an absent one. What this costs is Apple
Silicon users running under emulation. Stated rather than discovered.

**The image is not signed, and there is no SBOM.** Both are a `cosign` step and
a `syft` step, and both are the kind of thing that is worth adding when somebody
external actually consumes the image. Named here so that the absence is a
decision.

**The surface snapshot does not cover the policy file's grammar.** It covers the
schema module's shape only indirectly, through nothing at all — a rule keyword
could be renamed and this would not notice. `acp policy explain` would, loudly,
on the first run. Worth adding; not today.

**Nothing verifies that a *major* bump actually happened** when the surface
changed incompatibly. The snapshot makes the change visible; a human decides.
Automating it would need the rule "removed means major" encoded, and the rule
has exceptions — removing a setting that was never wired to anything is not a
breaking change, and this project shipped six of those.

## References

- ADR 0001 — one specification revision only, which is the wire half of this
- ADR 0008 — conformance against a server this project did not write
- ADR 0023 — prove the invariant, then prove the proof
- ADR 0050 — the audit record's shape, and why a chain must keep verifying
- `CHANGELOG.md` — what 1.0.0 does, and what it does not do
