"""Add Keycloak to `docker-compose.yml` without touching anything else in it.

`docker-compose.yml` is one of four files that carry local edits made on
Chandana's machine and not in the build sandbox, so shipping a whole copy would
silently revert them — that is bug 26, and this script exists so it does not
happen a second time.

Every edit asserts its anchor before writing. A slice or replace whose anchor is
missing has destroyed two files in this project already; an assertion turns that
into an exit code.

Idempotent: running it twice is a no-op with a message, not a doubled service.
"""

from __future__ import annotations

import sys
from pathlib import Path

PATH = Path("docker-compose.yml")

KEYCLOAK_SERVICE = """
  # -------------------------------------------------------------------------
  # The identity provider — task 26
  # -------------------------------------------------------------------------
  #
  # Everything in tasks 22 to 24 was tested against fakes written in this
  # repository, and a mock that agrees with your client proves only that you
  # wrote both. This is the first thing in the stack that can disagree with us.
  #
  # `start-dev` and not `start`: this is a demo realm on a laptop, HTTP-only,
  # with an in-container database. Running it in production mode would mean
  # provisioning Postgres and TLS to prove a point nobody is asking about.
  keycloak:
    # Pinned, like Jaeger and for the same reason: an identity provider that
    # silently changes how it issues tokens between runs turns "the gateway
    # rejects my token" into a question with two possible causes.
    image: quay.io/keycloak/keycloak:26.7.1
    container_name: acp-keycloak
    restart: unless-stopped
    command: ["start-dev", "--import-realm"]
    environment:
      # The whole reason this file names `keycloak:8080` everywhere rather than
      # `localhost`. An issuer is a public identity compared as an exact string
      # (RFC 8414 §2, ADR 0016), so it has to be one string from every vantage
      # point — and the gateway's vantage point is inside this network, where
      # `localhost` means the gateway itself. Setting the hostname explicitly
      # fixes what Keycloak stamps into `iss` regardless of which host a request
      # arrived on. See ADR 0018.
      KC_HOSTNAME: http://keycloak:8080
      KC_HTTP_ENABLED: "true"
      KC_HEALTH_ENABLED: "true"
      # Dev credentials for the admin console, in a file that is in git. They
      # unlock a realm containing two invented users and no data.
      KC_BOOTSTRAP_ADMIN_USERNAME: admin
      KC_BOOTSTRAP_ADMIN_PASSWORD: admin
    volumes:
      # Read-only. Keycloak imports the realm and never needs to write here, and
      # a config source an application can rewrite is a config source that tells
      # you nothing about what it was configured with.
      - ./config/keycloak:/opt/keycloak/data/import:ro
      #
      # There is deliberately no volume for the database. Dev mode keeps H2 under
      # /opt/keycloak/data/h2 — a directory the image does not contain, so a named
      # volume mounted there is created by Docker as root:root, and Keycloak, which
      # runs as uid 1000, dies on boot with AccessDeniedException.
      #
      # Persisting it was worth little anyway. The committed realm is the source of
      # truth, and a surviving database means console edits diverge silently from
      # the file in git.
    ports:
      # The admin console: http://localhost:8081 (admin / admin).
      - "8081:8080"

  # A one-shot readiness gate, deliberately built from *our* image.
  #
  # The gateway runs OIDC discovery at startup, before it binds a port, because
  # an issuer whose metadata contradicts its own identity should stop a
  # deployment rather than surprise the first request. That makes "Keycloak is
  # answering yet" a hard ordering dependency rather than a nicety.
  #
  # The usual way to express that is a healthcheck on the Keycloak container,
  # which means writing a probe out of whatever binaries that image happens to
  # ship — no curl, no wget, and a shell one-liner that breaks when the base
  # image changes. Polling from a container we control needs nothing from
  # theirs, and the failure message is one we wrote.
  keycloak-ready:
    build:
      context: .
      target: runtime
    image: acp/gateway:dev
    container_name: acp-keycloak-ready
    restart: "no"
    depends_on:
      keycloak:
        condition: service_started
    entrypoint: ["python", "-c"]
    command:
      - |
        import sys, time, urllib.error, urllib.request
        url = "http://keycloak:8080/realms/acp/.well-known/openid-configuration"
        deadline = time.monotonic() + 180
        last = "no attempt"
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=3) as response:
                    if response.status == 200:
                        print("keycloak: realm acp is serving metadata", flush=True)
                        sys.exit(0)
                    last = f"HTTP {response.status}"
            except (urllib.error.URLError, OSError) as exc:
                last = type(exc).__name__
            print(f"keycloak: waiting ({last})", flush=True)
            time.sleep(2)
        sys.exit(
            f"keycloak did not serve {url} within 180s; last attempt: {last}. "
            "`docker compose logs keycloak` is where the reason is."
        )
"""

GATEWAY_ENV = """      # -- identity, against the real thing (task 26) ----------------------
      #
      # The issuer is `keycloak:8080` and not `localhost:8081` because the
      # gateway resolves it from inside this network, and because `iss` is
      # compared as an exact string — one identity, one spelling, everywhere.
      ACP_AUTH_ISSUER: http://keycloak:8080/realms/acp
      # Audience and resource identifier are the same string on purpose: the
      # gateway publishes it under RFC 9728, a client asks for it as RFC 8707's
      # `resource`, and Keycloak's audience mapper writes it into `aud`. It is
      # `localhost:8080` because that is where a *client* reaches the gateway,
      # which is a different question from where the gateway reaches Keycloak.
      ACP_AUTH_AUDIENCE: http://localhost:8080/mcp
      ACP_AUTH_RESOURCE: http://localhost:8080/mcp
      # The assertion, not a switch. This deployment has an identity provider,
      # so a gateway here that resolved every request to `anonymous` is a
      # deployment that has failed, not one running in a different mode.
      ACP_AUTH_REQUIRED: "true"
      # And the price of a demo identity provider that speaks plain HTTP.
      # Narrow, named, and logged at every start — ADR 0018.
      ACP_AUTH_INSECURE_ISSUER_HOSTS: '["keycloak"]'
"""

GATEWAY_DEPENDS = """      keycloak-ready:
        condition: service_completed_successfully
"""


def fail(message: str) -> None:
    sys.exit(f"patch aborted: {message}")


def main() -> int:
    if not PATH.exists():
        fail(f"{PATH} not found — run this from the repository root")

    text = PATH.read_text(encoding="utf-8")

    if "acp-keycloak" in text:
        print("docker-compose.yml already has Keycloak; nothing to do.")
        return 0

    # 1. The gateway's `depends_on` gains the readiness gate.
    anchor = "    depends_on:\n      mock-a:\n        condition: service_healthy\n"
    if anchor not in text:
        fail("could not find the gateway's `depends_on` block")
    text = text.replace(anchor, anchor + GATEWAY_DEPENDS, 1)

    # 2. Identity settings, inserted just before the OpenTelemetry ones so the
    #    ACP_ variables stay together.
    anchor = "      # OpenTelemetry's own variables, not ACP_ ones."
    if anchor not in text:
        fail("could not find the OpenTelemetry comment in the gateway environment")
    text = text.replace(anchor, GATEWAY_ENV + anchor, 1)

    # 3. The two new services, before the trace backend's banner.
    rule = "  # " + "-" * 73 + "\n"
    anchor = rule + "  # Trace backend\n"
    if anchor not in text:
        fail("could not find the trace backend section")
    text = text.replace(anchor, KEYCLOAK_SERVICE + "\n" + anchor, 1)

    PATH.write_text(text, encoding="utf-8")
    print("docker-compose.yml patched: keycloak, keycloak-ready, gateway identity settings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
