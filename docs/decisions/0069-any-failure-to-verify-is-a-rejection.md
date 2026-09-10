# ADR 0069 — Any failure to verify is a rejection

**Status:** accepted
**Date:** 2026-09-10

## Context

`TokenValidator.validate` wrapped `jwt.decode` in `except
jwt.InvalidTokenError`, on the reasonable assumption that PyJWT signals a
rejected token with that class. It does not signal every one:

```python
jwt.decode(es256_token, key=rsa_public_key, algorithms=["ES256", "RS256"], ...)
# TypeError: Expecting a PEM-formatted key.        isinstance(..., InvalidTokenError) is False
```

The shape that produces it is ordinary: a header claiming `ES256` while the
`kid` names an RSA key. Any deployment whose registration lists both algorithm
families can be sent one, by anybody, unauthenticated.

`TypeError` is not `InvalidTokenError` and not `ACPError`, so it passed both
handlers in `identity/asgi.py` and left as an **HTTP 500 with a traceback**.

The crash is the smaller half. The larger half is that it made the rejection
path *informative*: an unknown `kid` answered 401 and a known `kid` with the
wrong key type answered 500. That difference is a map of the key set, readable
one request at a time by an unauthenticated caller — which is precisely what
`_rejected`'s single message was written to prevent, in a docstring that says
so.

## Decision

**Any exception out of `decode` is a rejection.** `except Exception`, re-raised
through the same `_rejected` path as every other cause, with the exception's
type name in `details` for the log.

`Exception` rather than an enumerated list. The next case of this is a PyJWT or
`cryptography` release away — the library's contract is about
`InvalidTokenError`, not about what its dependencies raise underneath — and a
list means rediscovering this with a 500 in production. Nothing is lost to
debugging: the type name still reaches the operational log, where it was already
going.

`BaseException` is deliberately not caught. A cancellation or a `MemoryError` is
not a bad token, and turning either into a 401 would be a worse bug than the one
being fixed.

## Alternatives considered

**Catch `(InvalidTokenError, TypeError, ValueError)`.** Fixes today's
reproduction and leaves the class of bug open. The reason this escaped is that
somebody enumerated the exceptions they had thought of.

**Pre-check that the key type matches the header's algorithm.** Correct, and it
re-implements a decision PyJWT already makes with more context than this module
has. A second implementation of a security check is a second thing to keep in
agreement (the argument ADR 0030 makes for one evaluator).

**Let it 500 and add a generic handler further out.** A blanket handler on the
ASGI app would stop the traceback and would not fix the oracle: the status codes
would still differ, because the two paths would still be different paths.

## Consequences

Every cause of a failed verification now produces the same 401 with the same
body. A test asserts it across five causes — expired, wrong audience, wrong
issuer, wrong key type, and a string that is not a token — and fails if any of
them is distinguishable on the wire.

A genuine bug inside `decode` — an argument this module passes wrongly — would
now be reported as a bad token rather than as a crash, which is a real cost: it
would be visible as a rise in `auth.rejected` with an unfamiliar `reason` rather
than as a stack trace. The reason field is what makes that survivable, and it is
why the type name is kept rather than discarded.

Both tests fail against the previous implementation with the `TypeError` above.
