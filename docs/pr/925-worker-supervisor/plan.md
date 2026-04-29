# #925: worker thread supervisor (Phase 1 — catch + report)

Plan v1 — 2026-04-29.

## Investigation findings (Claude, first-hand)

The #925 issue body claims that the minimal supervisor (`catch_unwind`
+ mark-dead atomic) was already landed as part of #913. **This is
false.** Grepping `userspace-dp/src/`:

- Zero `panic::catch_unwind` references in production code.
- `sharded_neighbor.rs:20` has a doc-comment that says: "Workers
  have no `catch_unwind` supervisor today (#925 deferred)."
- `tx.rs:4554` has another doc-comment referencing the same gap.

So #925 starts from zero, not from a "minimal supervisor already in
place; expand to respawn" baseline. This plan acknowledges that and
scopes Phase 1 accordingly.

## Spawn sites

`userspace-dp/src/afxdp/coordinator.rs` has three `thread::Builder::spawn`
sites that need supervision:

- **Line 716** — `worker_loop` per worker. The hot path. Highest
  priority for catch+report.
- **Line 807** — `neigh_monitor_thread` (netlink monitor). Different
  failure profile; defer to Phase 2.
- **Line 854** — `local_tunnel_source_loop` (per GRE tunnel). Defer
  to Phase 2.

This plan covers **the worker_loop site only**. The other two are
follow-ups in #925's broader scope but separate PRs.

## Existing infrastructure

- `WorkerRuntimeAtomics` (`worker_runtime.rs:62-90`) — cache-line
  isolated atomic struct already plumbed per worker. Has `tid`,
  `wall_ns`, `active_ns`, `work_loops`, `idle_loops`, etc. **The
  natural home for a `dead` flag and a panic-message slot.**
- `WorkerRuntimeStatus` (`protocol.rs:1043-1062`) — gRPC-published
  per-worker status struct with `#[serde(default)]` on every field
  for backward compat. Adding new fields is straightforward.
- `coordinator.worker_runtime_snapshots()` (`coordinator.rs:1216`)
  — already polls `WorkerRuntimeAtomics` and emits
  `WorkerRuntimeStatus`. Adding two fields here lights up the gRPC
  surface automatically.

## Phase 1 scope (this PR)

Three deliverables:

1. **Catch panics** in the worker_loop spawn closure.
2. **Report dead workers** via gRPC `WorkerRuntimeStatus`.
3. **Test coverage** with a panic-injection test.

Phase 2 (separate PRs, separately tracked):

- **Respawn**: detect dead worker, recreate BindingWorker state,
  re-attach UMEM/XSK rings, re-bind queues. Non-trivial — UMEM
  ownership and queue-binding mechanics need careful unwinding. Ship
  Phase 1 first to learn whether respawn is ever actually needed in
  practice.
- **Sticky-failure detection**: don't infinite-respawn. Trivial once
  Phase 2's respawn lands.
- **HA failover trigger**: when a worker dies on the primary node,
  optionally trigger chassis-cluster failover. Requires policy
  decisions (does ANY worker death failover, or only N workers dead
  on the primary?).
- **Other spawn sites** (neigh_monitor, local_tunnel_source). Same
  catch+report pattern; mechanical.

## Design

### `WorkerRuntimeAtomics` additions

```rust
#[repr(align(64))]
pub(crate) struct WorkerRuntimeAtomics {
    // ... existing fields unchanged ...
    pub tid: AtomicU64,
    /// #925 Phase 1: set to 1 when the worker_loop panics and is
    /// caught by `catch_unwind`. Once set, never cleared in this
    /// phase. Phase 2 (respawn) will clear it on successful relaunch.
    pub dead: AtomicBool,
    _pad: [u8; 0],
}
```

`AtomicBool` is 1 byte; with `#[repr(align(64))]` on the struct the
total layout is unchanged (still 64-byte aligned, no inter-worker
false sharing).

### Panic message slot

The panic payload needs to live somewhere the coordinator can read.
Options:

- **A.** `Arc<Mutex<Option<String>>>` per worker — heap, but only
  written once per panic (worker is dead by then). Simple.
- **B.** Lock-free SPSC queue — overkill for a one-shot event.
- **C.** Fixed-size byte buffer atomically published — complex.

Choosing **A**. The cost is paid only when a worker actually dies,
which is rare. Field name: `last_panic: Arc<Mutex<Option<String>>>`.
Lives outside `WorkerRuntimeAtomics` (it's a control-plane concept,
not a per-tick atomic) — store on `Coordinator` as
`worker_panics: Vec<Arc<Mutex<Option<String>>>>` indexed by worker
ID.

### `WorkerRuntimeStatus` additions

```rust
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WorkerRuntimeStatus {
    // ... existing fields unchanged ...
    /// #925: true if the worker thread panicked and was caught by
    /// the supervisor. Once set, the worker is no longer processing
    /// packets for its bound queues.
    #[serde(rename = "dead", default)]
    pub dead: bool,
    /// #925: panic payload string (if any), for operator diagnosis.
    /// Empty string when alive or when panic payload was non-string.
    #[serde(rename = "panic_message", default)]
    pub panic_message: String,
}
```

`#[serde(default)]` keeps wire compatibility with older daemons.

### Spawn closure rewrite

Currently (`coordinator.rs:716-748`):

```rust
let join = thread::Builder::new()
    .name(format!("xpf-userspace-worker-{worker_id}"))
    .spawn(move || {
        worker_loop(/* args */);
    })
    .expect("spawn worker");
```

After:

```rust
let panic_slot = Arc::new(Mutex::new(None::<String>));
let panic_slot_clone = panic_slot.clone();
let runtime_atomics_supervisor = runtime_atomics.clone();
let join = thread::Builder::new()
    .name(format!("xpf-userspace-worker-{worker_id}"))
    .spawn(move || {
        let result = std::panic::catch_unwind(
            std::panic::AssertUnwindSafe(|| {
                worker_loop(/* same args */);
            }),
        );
        if let Err(payload) = result {
            // Extract a printable message from the panic payload.
            let msg = panic_payload_message(&payload);
            slog::error!(slog_scope::logger(),
                "userspace-dp worker_loop panicked";
                "worker_id" => worker_id,
                "message" => &msg,
            );
            if let Ok(mut slot) = panic_slot_clone.lock() {
                *slot = Some(msg);
            }
            runtime_atomics_supervisor.dead.store(true, Ordering::Release);
        }
    })
    .expect("spawn worker");
self.worker_panics.push(panic_slot);
```

`AssertUnwindSafe` is required because `worker_loop` takes
non-`UnwindSafe` types (raw fds, `&mut` borrows). This is sound
because: on panic, those references are dropped; the supervisor
doesn't reuse them.

### `panic_payload_message` helper

```rust
fn panic_payload_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        format!("non-string panic payload of type {:?}",
                std::any::type_name_of_val(payload))
    }
}
```

### Coordinator status surfacing

In `coordinator.worker_runtime_snapshots()`:

```rust
crate::protocol::WorkerRuntimeStatus {
    worker_id: ...,
    // ... existing fields ...
    dead: atomics.dead.load(Ordering::Acquire),
    panic_message: self.worker_panics
        .get(worker_id as usize)
        .and_then(|slot| slot.lock().ok().and_then(|g| g.clone()))
        .unwrap_or_default(),
}
```

## Memory ordering

- `dead.store(true, Release)` on the panic-handler side.
- `dead.load(Acquire)` in `worker_runtime_snapshots`.
- The `Mutex`-protected panic message uses the mutex's
  acquire/release semantics; no additional barriers needed.

## Implementation steps

1. Add `dead: AtomicBool` to `WorkerRuntimeAtomics` (`worker_runtime.rs`).
2. Add `worker_panics: Vec<Arc<Mutex<Option<String>>>>` to
   `Coordinator` (`coordinator.rs`).
3. Add `dead: bool` and `panic_message: String` to
   `WorkerRuntimeStatus` (`protocol.rs`).
4. Add `panic_payload_message` helper (private, in `coordinator.rs`).
5. Wrap the `worker_loop` spawn closure at `coordinator.rs:716` in
   `catch_unwind` + on-Err mark-dead + log + slot publish.
6. Update `worker_runtime_snapshots()` to surface the new fields.
7. Unit tests (in `coordinator.rs::tests` or a new `supervisor.rs`):
   - Spawn a closure that panics with a string; verify `dead == true`
     after join.
   - Spawn a closure that panics with `i32` (non-string); verify the
     `panic_message` records "non-string panic payload of type i32".
   - Spawn a closure that does not panic; verify `dead == false`.
8. (Optional integration test) Inject a panic via a debug-only
   `WorkerCommand::PanicInjection` that the test driver can fire,
   then verify gRPC status reflects the dead worker. Defer to Phase 2
   if the unit tests are sufficient.

## Acceptance gates

1. `cargo build --release` clean.
2. `cargo test --release` ≥ 825 + 3 new = 828 / 828 pass.
3. Cluster smoke (HARD): no regression — supervisor wrapping should
   be zero-cost in the no-panic path.
   - iperf-c P=12 ≥ 22 Gb/s
   - iperf-c P=1 ≥ 6 Gb/s
   - iperf-b P=12 ≥ 9.5 Gb/s, 0 retx
4. Manual injection (recommended, not gated): hot-patch a panic into
   `worker_loop` (or use a feature-flagged `panic-injection-test`
   build), restart the daemon, observe dead-worker status via
   `cli show chassis forwarding workers` (or whatever surfaces
   `WorkerRuntimeStatus`). Verify the daemon stays up and other
   workers continue.
5. Codex hostile review: AGREE-TO-MERGE.
6. Gemini adversarial review: AGREE-TO-MERGE.

## Risk

**Medium-low.**

- `catch_unwind` semantics are well-understood Rust stdlib.
- `AssertUnwindSafe` is the only soundness footgun; the closure
  doesn't share state with anyone after the panic, so it's correct
  here.
- Adding gRPC fields with `#[serde(default)]` is wire-compatible.
- The hot path is unaffected — `catch_unwind` only intercepts
  unwinding, not normal returns. There's literature claiming
  ~5-10ns/call overhead even on the no-panic path due to landing-pad
  setup, but `worker_loop` is called once per spawn, not per packet,
  so the impact is "0 ns/packet."

## Risk on hot path: zero

`catch_unwind` is invoked ONCE per spawn (i.e., once per worker
lifetime). The packet-processing loop inside `worker_loop` is
unchanged. There is no per-packet or per-batch landing-pad cost.

## Out of scope

- Respawn (Phase 2)
- Sticky-failure detection (Phase 3)
- HA failover trigger (Phase 4)
- `neigh_monitor_thread` and `local_tunnel_source_loop` supervision
  (separate PRs, mechanical)
- Panic injection as a production feature (only for tests)

These all live under #925 in the issue tracker; this PR is
**Phase 1: catch + report**, the foundation.
