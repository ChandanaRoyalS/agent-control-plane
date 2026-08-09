"""Turn on token exchange in the composed gateway — task 27.

`docker-compose.yml` carries local edits and is never shipped whole (bug 26).
Asserted anchor, idempotent.
"""

from __future__ import annotations

import sys
from pathlib import Path

PATH = Path("docker-compose.yml")

ANCHOR = """      # And the price of a demo identity provider that speaks plain HTTP.
      # Narrow, named, and logged at every start — ADR 0018.
      ACP_AUTH_INSECURE_ISSUER_HOSTS: '["keycloak"]'
"""

ADDITION = """      # -- token exchange (task 27) ----------------------------------------
      #
      # Who the gateway *is* when it asks the authorization server for a
      # credential. Distinct from ACP_AUTH_AUDIENCE above, which is what the
      # gateway is *called* by tokens arriving at it — resource server there,
      # OAuth client here, and conflating the two is the easy mistake.
      #
      # Setting both of these is what turns exchange on: there is no boolean,
      # because a credential is not something you can forget to supply and still
      # have the feature appear to work. Once on, every upstream must declare an
      # `audience` or the gateway refuses to start.
      ACP_AUTH_CLIENT_ID: acp-gateway
      # In git, and a fixture rather than a secret — see config/keycloak/README.
      # A real deployment mounts this at /run/secrets/auth_client_secret and
      # never puts it in the environment, because a process's environment is
      # readable by anything that can see /proc.
      ACP_AUTH_CLIENT_SECRET: dev-only-not-a-secret-either
"""


def main() -> int:
    if not PATH.exists():
        sys.exit("patch aborted: docker-compose.yml not found — run from the repository root")

    text = PATH.read_text(encoding="utf-8")
    if "ACP_AUTH_CLIENT_ID" in text:
        print("docker-compose.yml already has token exchange configured; nothing to do.")
        return 0
    if ANCHOR not in text:
        sys.exit(
            "patch aborted: could not find the ACP_AUTH_INSECURE_ISSUER_HOSTS block.\n"
            "Nothing was written. Add ACP_AUTH_CLIENT_ID and ACP_AUTH_CLIENT_SECRET to the\n"
            "gateway's environment by hand instead (see ADR 0019)."
        )

    PATH.write_text(text.replace(ANCHOR, ANCHOR + ADDITION, 1), encoding="utf-8")
    print("docker-compose.yml patched: the gateway now mints per-upstream credentials.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
