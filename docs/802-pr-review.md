ROUND 1: NOT merge-ready

## Hot-path discipline
Clean.

## Counter aggregation timing
Clean.

## Overflow semantics
Clean.

## outstanding_tx proxy quality
Clean.

## Wire-key backward compatibility
Clean.

## dbg_pending_overflow semantic (the PARTIAL finding) — does the counter name match what it counts?
MAJOR | `dbg_pending_overflow` is published as “bound_pending” FIFO overflow while the increment site in the TX enqueue path also increments it for CoS queue overflow, so the operator-facing counter conflates two different saturation paths in one metric and can mislead root-cause triage | `userspace-dp/src/protocol.rs:1329-1330`, `userspace-dp/src/afxdp/tx.rs:157`, `userspace-dp/src/afxdp/tx.rs:176`, `userspace-dp/src/afxdp/tx.rs:5400` | Split the telemetry into distinct counters (or rename/clarify the field and docs) so `bound_pending` and CoS-queue admission overflow are not indistinguishable in the API payload.
