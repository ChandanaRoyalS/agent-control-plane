# The gateway as a container image.
#
# Two stages, because the things needed to *build* a Python application and the
# things needed to *run* one barely overlap. The builder has uv, a compiler
# toolchain and the lockfile; none of that reaches the runtime image, which
# carries an interpreter and a virtualenv and nothing else.
#
# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

# 3.14 while `pyproject.toml` says `>=3.12`, and the two are not in conflict:
# a package declares the range it supports, a deployment picks one point in it.
# The floor is not decoration either — CI's `compat` job runs the suite on 3.12,
# so the range is a tested claim rather than an aspiration.
FROM python:3.14-slim AS builder

# uv is installed rather than pinned to a specific release on purpose. It is a
# build tool, and the lockfile — not the installer — is what makes this image
# reproducible: `uv.lock` pins every version that actually lands in the venv,
# and UV_FROZEN turns a stale lockfile into a failed build rather than a
# silent re-resolution. Pinning uv as well would add a version to maintain
# without adding a guarantee.
RUN pip install --no-cache-dir uv

ENV UV_FROZEN=1 \
    UV_NO_CACHE=1 \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /build

# Dependencies first, source second, and the order is the whole point. Third
# party dependencies change monthly; source changes every commit. Copying
# source before installing dependencies would invalidate the dependency layer
# on every single build and re-download the world to change one line.
COPY pyproject.toml uv.lock ./
RUN uv sync --no-dev --no-install-project

COPY README.md ./
COPY src/ src/

# The mock upstream fleet is test infrastructure that happens to live inside
# the package (ADR 0004), so without this it would ship in the production
# image — two HTTP servers with deliberately controllable failure modes, in an
# artifact whose whole purpose is to be a security boundary. Removed *before*
# the install rather than deleted afterwards: a file deleted in a later layer
# is still recoverable from the earlier one, so "removed" would be a claim
# this image could not honour.
ARG WITH_MOCKS=false
RUN if [ "$WITH_MOCKS" != "true" ]; then rm -rf src/acp/mocks; fi

# `--no-editable` installs a real copy into the venv. The default would leave a
# path entry pointing at /build/src, which does not exist in the runtime stage
# — an image that imports fine here and fails on first start there.
RUN uv sync --no-dev --no-editable

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------

FROM python:3.14-slim AS runtime

# PYTHONUNBUFFERED is not cosmetic. Container stdout is a pipe, not a terminal,
# so Python block-buffers it — logs arrive in 8KB clumps, or not at all until
# the process exits, which for a crashing container means the output explaining
# the crash is the output you never see. This is bug 21 one level up: the same
# buffering rule that made `acp schemas check` print its advice above the drift
# it referred to.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH"

# A fixed UID, not whatever the base image assigns next. Anything bind-mounting
# a volume into this container has to reason about file ownership, and "some
# number between 999 and 1001 depending on the base image" is not something a
# deployment can be written against. 10001 is above the range Debian hands out
# to system accounts, so it cannot collide with one.
RUN groupadd --gid 10001 acp \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin acp

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app

# Baked in so the image runs standalone with no orchestration at all. Compose
# mounts the host's `config/` over the top, read-only — see the compose file for
# why read-only is a security property and not tidiness.
COPY config/ config/

USER acp

EXPOSE 8080 9090

# `/healthz`, deliberately, and never `/readyz`.
#
# Docker restarts unhealthy containers. `/readyz` reports 503 when every
# upstream is down — which is somebody else's outage — so wiring it here would
# turn one broken upstream into a crash loop of a gateway that is working
# perfectly. That is the exact distinction task 18 drew when the two endpoints
# were split, and this is where getting it wrong would cost something.
#
# urllib rather than curl: the image has no curl, and adding one so the
# healthcheck can run would mean shipping an HTTP client to a container that
# already contains one.
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request as u,sys; sys.exit(0 if u.urlopen('http://127.0.0.1:9090/healthz',timeout=2).status==200 else 1)"

ENTRYPOINT ["acp"]
CMD ["serve"]
