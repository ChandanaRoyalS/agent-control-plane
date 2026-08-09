"""Remove Keycloak's database volume — the first CI run of this stack found it broken.

`/opt/keycloak/data/h2` does not exist in the Keycloak image, so Docker creates
it for a named volume as `root:root`. Keycloak runs as uid 1000, cannot write
its H2 database, and dies on boot with `AccessDeniedException`. The container
then spends two minutes retrying the JDBC connection while the readiness gate
polls a port nothing is listening on.

Persisting it bought little in the first place. The committed realm is the
source of truth, and a database that survives means console edits diverge
silently from the file in git — so this removes a failure mode and a source of
confusion at the same time.

`docker-compose.yml` carries local edits and is never shipped whole (bug 26).
Every edit below asserts its anchor before writing, and the script is
idempotent.
"""

from __future__ import annotations

import sys
from pathlib import Path

PATH = Path("docker-compose.yml")

OLD_VOLUME = """      # Dev mode keeps its H2 database under data/. Named, so a restart does not
      # silently discard whatever was clicked in the console — and so
      # `make idp-reset` has something definite to remove when the committed
      # realm changes. Keycloak skips the import when the realm already exists,
      # which is the right default and the reason editing the realm file appears
      # to do nothing until the volume goes.
      - keycloak-data:/opt/keycloak/data/h2
"""

NEW_VOLUME = """      #
      # There is deliberately no volume for the database. Dev mode keeps H2 under
      # /opt/keycloak/data/h2 — a directory the image does not contain, so a named
      # volume mounted there is created by Docker as root:root, and Keycloak, which
      # runs as uid 1000, dies on boot with AccessDeniedException. That is what the
      # first CI run of this stack found, after two minutes of JDBC retries.
      #
      # Persisting it was worth little anyway. The committed realm is the source of
      # truth, and a surviving database means console edits diverge silently from
      # the file in git. Without one, every recreated container re-imports the
      # realm and there is one fewer piece of state to explain. A container that is
      # merely restarted still keeps its database, which is why `make idp-reset`
      # recreates rather than restarts.
"""

OLD_TOP_LEVEL = """
# ---------------------------------------------------------------------------
# Volumes
# ---------------------------------------------------------------------------
volumes:
  # Keycloak's dev-mode database. See the comment on the service for why this
  # is named rather than anonymous, and what `make idp-reset` is for.
  keycloak-data:
"""

OLD_HINT = '        sys.exit(f"keycloak did not serve {url} within 180s; last: {last}")'
NEW_HINT = (
    "        sys.exit(\n"
    '            f"keycloak did not serve {url} within 180s; last attempt: {last}. "\n'
    '            "`docker compose logs keycloak` is where the reason is."\n'
    "        )"
)


def fail(message: str) -> None:
    sys.exit(f"patch aborted: {message}")


def main() -> int:
    if not PATH.exists():
        fail(f"{PATH} not found — run this from the repository root")

    text = PATH.read_text(encoding="utf-8")

    if "keycloak-data" not in text:
        print("docker-compose.yml already has no keycloak database volume; nothing to do.")
        return 0

    if OLD_VOLUME not in text:
        fail("could not find the keycloak-data mount in the keycloak service")
    text = text.replace(OLD_VOLUME, NEW_VOLUME, 1)

    if OLD_TOP_LEVEL not in text:
        fail("could not find the top-level `volumes:` block")
    text = text.replace(OLD_TOP_LEVEL, "", 1)

    # Best-effort: the readiness message gained a pointer to the logs. Not fatal
    # if it has already been edited by hand.
    if OLD_HINT in text:
        text = text.replace(OLD_HINT, NEW_HINT, 1)

    PATH.write_text(text.rstrip("\n") + "\n", encoding="utf-8")
    print("docker-compose.yml patched: keycloak's database volume removed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
