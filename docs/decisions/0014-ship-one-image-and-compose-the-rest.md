# ADR 0014 — Ship one image; compose the rest

**Status:** accepted
**Date:** 2026-08-07

## Context

Everything built so far runs from a checkout with `uv`. That is fine for
development and useless as evidence: a reader cannot try it without installing a
Python toolchain first, and nothing has ever proved that the application works
outside the environment it was written in.

Packaging is also the first thing that exercises the *production* dependency
set. Every test run to date installs with `--all-groups`, so the split between
runtime and development dependencies has never been tested at all — it has only
been written down.

## Decision

One multi-stage image built with `uv`, running as a fixed non-root UID, plus a
Compose file that assembles the gateway, both mock upstreams and Jaeger into a
system that `docker compose up -d --wait` brings to a known-good state.

CI builds the images, asserts two properties of them, brings the stack up and
runs a smoke test that makes a real MCP request and then checks the spans for it
arrived in the trace backend.

## What building it immediately found

`starlette` and `uvicorn` were declared in the **dev** dependency group while
`acp.admin`, `acp.runtime`, `acp.gateway.server` and `acp.cli` import them on
the runtime path. A `--no-dev` install produces an image where `acp serve` dies
on import.

Nothing caught this and nothing could have: the test suite installs everything,
so the only build that would have failed was one nobody was running. They arrived
transitively through `mcp` on the development machine, which is a fact about
today's resolution rather than a contract. **If you import it, declare it.**

## Alternatives considered

**A single-stage image.** Simpler, and it ships uv, a compiler toolchain and the
lockfile into production. The rule is that the runtime image should contain what
is needed to *run*, and the overlap between that and what is needed to *build* is
almost nothing.

**Copy source before installing dependencies.** The obvious ordering and the
expensive one. Dependencies change monthly, source changes every commit; putting
source first invalidates the dependency layer on every build and re-downloads the
world to change one line.

**Pin uv to an exact version in the builder.** Considered and rejected, which is
unusual for this project. `uv.lock` pins every version that actually lands in the
image, and `UV_FROZEN` turns a stale lockfile into a failed build. Pinning the
installer as well would add a version to maintain without adding a guarantee —
the lockfile is the reproducibility contract, not the tool that reads it.

**Install the project editable.** The default, and it leaves a path entry
pointing at the builder's `/build/src`, which does not exist in the runtime
stage. An image that imports fine during the build and fails on first start is
the worst of both worlds. `--no-editable` copies it in properly.

**Distroless for the runtime stage.** Smaller and more locked down, and it costs
the ability to `docker exec` into a misbehaving gateway — for a component whose
entire job is to be inspected, that is the wrong trade at this stage. It also
would have complicated the healthcheck, which currently uses the interpreter that
is already there rather than an added HTTP client.

**Let the mocks ship in the production image.** They live inside the package
(ADR 0004), so this is what happens by default: two HTTP servers with
deliberately controllable failure modes, inside an artifact whose purpose is to
be a security boundary. A `WITH_MOCKS` build argument removes them *before* the
install rather than deleting them afterwards — a file deleted in a later layer is
still recoverable from the earlier one, so "removed" would be a claim the image
could not honour. CI asserts `import acp.mocks` fails in the gateway image,
because a claim like that is exactly the kind that quietly stops being true.

**Bake configuration into the image only.** The image does contain `config/`, so
it runs standalone with no orchestration at all. Compose then mounts the host's
`config/` over the top — **read-only**, which is a security property rather than
tidiness: the schema baseline is the record a drift alert is measured against
(ADR 0013), so a gateway that can write to it is a gateway that can silence its
own alarm.

**Wire the container healthcheck to `/readyz`.** Tempting, since readiness is
the more informative endpoint, and wrong for the same reason task 18 split the
two in the first place. Docker restarts unhealthy containers, and `/readyz`
reports 503 when every upstream is down — somebody else's outage. Wiring it here
would turn one broken upstream into a crash loop of a gateway that is working
perfectly.

**A bash-and-`jq` smoke test.** It has to parse JSON, decode an SSE frame and
assert on both. The host is guaranteed to have a Python that can do all three and
is not guaranteed to have `jq`.

**Assert only that containers started.** The check that matters is not "did
Docker run this". It is that a real MCP request, carrying the 2026-07-28
envelope, crosses the gateway into a containerised upstream, returns six
qualified tools, and that the spans for it arrive in a *different container's*
trace backend. Anything less proves the images exist, not that the system is
assembled.

## Consequences

`docker compose up -d --wait` is now the fastest path from clone to a running,
traced, drift-monitored gateway, and it is the path a reader will take. The
README's quickstart changes accordingly.

There are two images, not one — `acp/gateway:dev` and `acp/mocks:dev` — with
separate tags specifically so the mock-bearing build cannot be deployed by
reaching for the wrong name.

The mock services' healthcheck is a TCP connect, and it is worth being precise
about what that proves: the listener is bound, not that the protocol works. MCP
has no health method, and inventing one for the mocks would test the invention.
Proving the protocol works is the gateway's own health prober's job (task 18) —
the layer that can actually judge it.

CI now takes longer. Building an image on every pull request is the cost of
knowing the image builds, and a Dockerfile that is not built by CI is a
Dockerfile that is broken the next time somebody needs it.
