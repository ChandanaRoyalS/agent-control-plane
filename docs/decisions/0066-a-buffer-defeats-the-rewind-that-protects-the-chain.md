# ADR 0066 — A buffer defeats the rewind that protects the chain

**Status:** accepted
**Date:** 2026-09-10

## Context

`FileAuditSink.append` chains an entry, writes it, and on `OSError` rewinds the
chain so the sequence number is reused rather than skipped. The reasoning in its
docstring is correct and worth keeping: *a gap is indistinguishable from a
deletion to anybody reading later*, so a transient disk error must not be
permanently recorded as evidence of tampering.

A second review of v1.0.0 pointed out that a buffered writer silently defeats
it, and it reproduces in four lines. CPython's `BufferedWriter` keeps the bytes
it could not flush. So the failed line is still in the buffer, and the *next*
successful flush emits it first and the retried line after it:

```
append 2: OSError(28) — chain rewound, seq reused
seqs on disk: [1, 2, 2, 3]
chain breaks: sequence jumped from 2 to 2
              prev does not match the previous entry's hash
```

One transient `ENOSPC` and `acp audit verify` reports tampering, permanently, on
a file nobody touched. For a component whose entire purpose is to be believed
when it says the record is intact, this is the worst available failure: it
manufactures the exact evidence it exists to detect.

**The existing test passed against it.** `test_a_failed_write_leaves_no_gap`
substituted the handle for a double with no buffer, so the property in its own
name was never exercised. That is the sharper half of the finding: the bug was
not merely uncaught, it was covered by a test that reported on it.

## Decision

**Write raw, unbuffered.** `path.open("ab", buffering=0)`. A write reaches the
descriptor or it does not, and there is no hidden copy to replay. The rewind
that was always right now works.

**Count what landed in the file, not what `write` returned.** A raw write can
raise *after* putting bytes on the descriptor, in which case its return value
never arrives — so a byte counter misses precisely the case that matters. The
size of the file before and after is the honest measure; in append mode every
write lands at the end.

**A torn write stops the sink.** If any bytes landed, the entry cannot be
rewound: reusing the sequence number would append a valid record *behind* a
truncated one and carry the damage into the middle of a file that still looks
mostly fine. Instead every later append refuses, naming the file. The tail stays
the last thing in it, which is where somebody will actually find it.

**And the test patches the raw descriptor.** A full disk fails when the kernel
is asked to take bytes, underneath whatever buffer exists. The helper reaches
through to `BufferedWriter.raw` when there is one and to the handle itself when
there is not — so the same test exercises the real failure against either
implementation. All three sink-failure tests fail against the previous code with
the reproduction above, and pass against this one.

## Alternatives considered

**Reopen the handle on `OSError`.** Plausible and wrong in a way worth writing
down: `close()` *flushes*, so closing a handle whose buffer holds the failed
line writes that line on the way out. The fix would perform the bug. Discarding
without flushing means reaching into the buffer's internals, which is a
CPython detail this project should not depend on.

**Keep the buffer and flush after every write.** Works, and leaves a loaded gun
on the table: the correctness of the chain would depend on a `flush()` call
nobody can see the importance of, and the next person who moves it for
throughput reintroduces this. Unbuffered makes the property structural.

**Accept the gap instead of rewinding.** Skipping the sequence number avoids the
duplicate, and trades a false tampering signal for a different one — a hole in
the sequence, which is exactly what a deleted record looks like. The original
reasoning stands; only its implementation was broken.

## Consequences

A per-entry write is now one syscall with no buffering, which is *cheaper* than
the previous write-plus-flush pair, not more expensive. `fsync` is unchanged and
still the dominant cost when enabled (ADR 0054: 5.8 ms).

A torn write turns the sink into a brick until a human looks at the file. That
is deliberate and it is the fail-closed direction: with `audit_required` on —
the default — the gateway then refuses calls rather than serving them
unrecorded, which is what ADR 0050 asks for.

What would make us revisit: evidence that unbuffered writes hurt throughput
enough to matter. The measurement to run is ADR 0054's, and the prediction to
write down first is that it will not, because `fsync` dwarfs it.
