# #5800 — io_uring write: ring-owned in-flight registry (UAF fix)

## Goal
Close the memory-lifetime violation in `userspace-dp/src/io_uring_write.rs`:
`write_all()` submits a Write SQE that borrows the caller's buffer; on
`MAX_WAIT_RETRIES` exhaustion (or a fatal ring error) it returns while the SQE
may still be in flight, and the caller frees the buffer → UAF-class disclosure /
corruption / crash. Also: `user_data` restarts at `1` every call → a stale CQE
can alias a later call.

## Required invariants (issue = spec)
1. Never return while an in-flight SQE references caller-borrowed storage.
2. Release a buffer owner only after ONE terminal state: matching CQE reaped,
   cancellation CQE reaped, OR ring teardown/drain proving no kernel refs.
3. `user_data` unique for the ring lifetime; wrap fail-closed.
4. Fatal-ring handling retains all in-flight owned buffers until teardown/drain.
5. The latency ceiling may stop a worker; it may NOT weaken memory lifetime.

## Approach
Introduce a **ring-owned in-flight registry** that OWNS the packet bytes and
vends a **ring-global monotonic `user_data`**. `write_all` takes the buffer by
value (`Vec<u8>`); moving a `Vec` preserves its heap allocation address, so the
SQE pointer stays valid when the buffer is moved into the registry.

- `InflightRegistry { next_id: u64, inflight: Vec<InFlightWrite> }`.
  - `alloc_id()` monotonic from 1; returns `None` when the space is exhausted
    (never wraps back through 0 or reuses a live id) → `write_all` fails closed
    WITHOUT submitting (invariant 3).
  - `reap_ready(port)` — non-blocking: pop ready CQEs, RELEASE the matching
    registry entry (drop its buffer — the kernel is done), discard true stale.
    Called at the top of every `write_all` and inside `reap_matching`'s reap
    loop so a deferred op's completion frees its buffer opportunistically.
  - `drain_for_teardown(port)` — bounded: submit an `AsyncCancel` for every live
    entry, then reap until BOTH the cancel's CQE AND the target write's terminal
    CQE are observed before dropping each buffer (cancellation submission alone
    is insufficient). Ceiling-bounded; un-drained entries are RETAINED (freed
    only when the registry drops, i.e. AFTER the ring fd closes).
- `write_all(port, reg, data: Vec<u8>, positioned, label) -> WriteResult`:
  - `Done(Vec<u8>)` — every byte written + matching CQE reaped; buffer safe.
  - `NothingWritten(Vec<u8>, msg)` — nothing on the fd (push fail / kernel error
    / zero byte / id-exhaustion); buffer handed back; sync-retry safe.
  - `Transferred(Vec<u8>, msg)` — packet-fd partial: reaped (terminal) so buffer
    safe, but re-send would corrupt → caller drops, never retries.
  - `Deferred { id, message, fatal_ring }` — NOT terminal (ceiling / fatal ring):
    buffer MOVED into `reg`; caller must not free/retry.
- `reap_matching` returns `Result<i32, ReapError{message, fatal_ring}>`;
  `fatal_ring` = `is_permanent(errno)`.
- `RingWriter { ring: IoUring, inflight: InflightRegistry }` bundles the
  persistent ring + registry. **Field order is load-bearing** (invariant 4):
  `ring` drops first (close fd → kernel cancels+waits in-flight ops), THEN
  `inflight` drops (frees buffers, no kernel ref can remain). `Drop` also runs a
  best-effort bounded `drain_for_teardown`.

## Both callers (acceptance: TUN packet writes AND positioned state writes)
- **Slow path** (`slowpath.rs`): `WriteMode::IoUring(RingWriter)`. `req.bytes`
  moves into `RingWriter::write`. New status counter `deferred_inflight`; a
  `Deferred{fatal_ring:true}` demotes to sync (mirrors #2958/#0faef94). A pure
  `classify_slow_path(&WriteResult) -> SlowPathAction` replaces
  `decide_sync_fallback` (keeps the #2477 sync-only-when-nothing-written
  decision unit-testable without a ring).
- **State writer** (`state_writer.rs`): `WriteMode::IoUring(RingWriter)`.
  `req.data: Vec<u8>` threads by value; `NothingWritten` hands it back for the
  sync fallback; `Deferred` demotes to sync and returns an error (NO sync
  retry — ambiguous). `Done` hands the buffer back so a `finalize_durably`
  failure can still sync-retry.

## Tests (fail-on-revert; drive the FakeRing seam)
- ceiling EINTR → entry OWNED in registry post-exhaustion (not freed) until a
  later reap/teardown releases it (invariant 1/5) — binds the defer branch.
- repeated transient (EAGAIN) → same.
- permanent error after submission (EBADF) → Deferred{fatal_ring:true}, retained.
- cancellation race: drain releases only after BOTH cancel CQE + target CQE.
- stale CQE not misattributed (retain existing test intent).
- id-wrap fail-closed: alloc_id at u64::MAX → next None → NothingWritten, no submit.
- regression: buffer stays owned after exhaustion until terminal completion.
Each new test binds a specific production line; neutralizing that line (a
COMPILING neutralization) turns exactly that test RED as an assertion failure.

## Alternatives rejected
- Copy-on-defer into the registry: WRONG — the SQE points at the caller's
  allocation, not the copy; the caller still frees the referenced memory.
- Caller-side retain (tell caller "in flight, don't free"): the issue mandates a
  ring-owned registry, and it centralises the lifetime proof + teardown drain.
- Rely on `IoUring` Drop alone for teardown: the kernel's ring-exit cancel+wait
  may be deferred off the close() path, so Drop order is necessary but the
  explicit bounded cancel-drain is what PROVES no refs in the common case.

## Docs
Update `docs/xdp-io-uring-userspace-dataplane.md` (slow-path write section) to
describe the in-flight registry + ring-global id + teardown drain.

## Implementation notes / deviations from the sketch above
- Kept the existing `classify_io_uring_write` / `SlowPathWriteOutcome` names
  (rather than introducing `classify_slow_path` / `SlowPathAction`) — the
  existing #5172 shape already carries `ring_terminal` + `demotion_cause`, so the
  four outcomes map onto it cleanly and the existing demotion tests keep binding.
- **No new `deferred_inflight` WIRE counter.** Adding a field to
  `protocol::control::SlowPathStatus` is a wire-contract change that forces
  regenerating the `protocol_wire_v1.json` golden fixture — out of scope for a
  UAF lifetime fix (engineering-style: narrow scope; wire changes get their own
  PR). The acceptance criterion "slow-path status distinguishes deferred
  in-flight ownership / successful completion / cancellation / fatal ring
  teardown" is met by the internal `SlowPathWriteOutcome` classification plus the
  operator-visible `last_error` (a `Deferred` now names the parked in-flight id)
  and the existing drop / write-error counters. A deferred packet is counted as a
  drop (it did not reliably reach the TUN).
- State writer: a `Deferred` FAILS the persist (its buffer is parked in the ring,
  not sync-retried — the buffer is no longer ours and the op may be in flight)
  and demotes to sync; a `NothingWritten` or a durable-finalize failure hands the
  buffer back for a synchronous rewrite to a FRESH temp (preserving the #2958
  fallback for every reaped-terminal outcome). `Transferred` is unreachable for a
  positioned write and is mapped defensively onto the sync-retry path.
- FakeRing seam: `push_cancel` queues the cancel's (and, when modelled, the
  target write's) completion as PENDING, surfaced only on a subsequent SUCCESSFUL
  `submit_and_wait_one`. This models the kernel (a cancel is reaped only once a
  wait submits it) and is what lets `fatal_ring_drain_retains_buffer` prove a dead
  ring cannot reap — its parked buffer is retained until registry drop.
