ROUND 2: merge-ready YES
## Round 2 verification
PASS — all four claims below validated.

1. `BindingLiveState` has both new counters, `dbg_bound_pending_overflow` and `dbg_cos_queue_overflow`, in `userspace-dp/src/afxdp/umem.rs:954-968`.
2. Increment attribution is split: `bound_pending_tx_local` and `bound_pending_tx_prepared` increment only `binding.dbg_bound_pending_overflow` (`userspace-dp/src/afxdp/tx.rs:160, 182`) while `enqueue_cos_item` increments only `binding.dbg_cos_queue_overflow` (`userspace-dp/src/afxdp/tx.rs:5406-5412`).
3. Wire-key hygiene is correct: split keys exist as `dbg_bound_pending_overflow` and `dbg_cos_queue_overflow` in Rust wire structs (`userspace-dp/src/protocol.rs:1316-1319`, `1360-1365`, `1386-1389`), and `dbg_pending_overflow` is no longer present in serde/json tags there.
4. Go consumer decodes both counters via `ControlResponse/ProcessStatus` JSON decode (`pkg/dataplane/userspace/process.go:185-200`) into fields that are present in Go structs (`pkg/dataplane/userspace/protocol.go:668-671`, `700-701`), with comments documenting pre-#804 zero-value compatibility (`pkg/dataplane/userspace/protocol.go:659-667`, `692-699`).

Blocking issues: none.

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
