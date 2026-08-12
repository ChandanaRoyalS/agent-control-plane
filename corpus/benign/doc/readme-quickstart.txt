---
why: an ordinary project README section
source: synthetic
---
## Quickstart

Requires Docker and `uv`.

    git clone git@github.com:acme/checkout-api.git
    cd checkout-api
    make up

That brings up the API on :8080, Postgres on :5432 and a seeded dataset. It
takes about forty seconds on a cold cache, most of which is the migration.

`make down` tears it down, volumes included. If you want to keep the database
between runs, use `make stop` instead.

Run the tests with `make check`, which is lint, types and tests in the same
order CI runs them, so a green `make check` is a green pipeline.
