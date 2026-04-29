# #925: worker thread supervisor (Phase 1 — catch + report)

Plan v2 — 2026-04-29. Addresses Codex hostile review (task-mojjrq43-8h1u9c, NEEDS-REVISION).

## Investigation findings (Claude, first-hand)

The #925 issue body claims that the minimal supervisor (`catch_unwind`
+ mark-dead atomic) was already landed as part of #913. **This is
false.** Grepping `userspace-dp/src/`:

- Zero `panic::catch_unwind` references in production code.
- `sharded_neighbor.rs:20` and `tx.rs:4553` have doc-comments that
  explicitly say "Workers have no `catch_unwind` supervisor today
  (#925 deferred)."

So #925 starts from zero, not from a "minimal supervisor already in
place; expand to respawn" baseline. This plan acknowledges that and
scopes Phase 1 to **catch + report** only, with respawn / sticky-
failure / HA-trigger explicitly deferred to follow-up phases.

## Spawn sites

`userspace-dp/src/afxdp/coordinator.rs` has three
`thread::Builder::spawn` sites that need supervision:

- **Line 716** — `worker_loop` per worker. The hot path. Highest
  priority for catch+report. **This PR.**
- **Line 807** — `neigh_monitor_thread`. Different failure profile;
  discards the `JoinHandle` (`.spawn(...).ok()`). A panic dies
  silently except for stderr. **Defer to Phase 2** — different code
  shape, harmless to land separately.
- **Line 854** — `local_tunnel_source_loop`. Stores a `JoinHandle`
  in `endpoint` state but doesn't monitor it. **Defer to Phase 2.**

This plan covers **the worker_loop site only**.

## Existing infrastructure

- `WorkerRuntimeAtomics` (`worker_runtime.rs:62-90`) — cache-line
  aligned (`#[repr(align(64))]`) atomic struct. Currently exactly
  8 × `AtomicU64` = 64 bytes.
- `WorkerRuntimeStatus` (`protocol.rs:1043-1062`) — Rust JSON struct
  emitted by the helper to the Go side. All fields use
  `#[serde(rename = "..", default)]`.
- Go-side mirror: `pkg/dataplane/userspace/protocol.go:528-538` —
  `WorkerRuntimeStatus` Go struct with matching `json:"..,omitempty"`
  tags. Decoded at `process.go:199` via `json.NewDecoder` (does NOT
  use `DisallowUnknownFields`, so unknown fields are tolerated).
- Display: `pkg/dataplane/userspace/statusfmt.go:307-329` — formats
  the worker runtime table for `cli show chassis forwarding`.

## Phase 1 scope (this PR)

Three deliverables:

1. **Catch panics** in the worker_loop spawn closure.
2. **Report dead workers** via JSON `WorkerRuntimeStatus` → Go-side
   decode → CLI display.
3. **Test coverage** with a `#[cfg(test)]` panic injection that
   exercises the actual spawn / snapshot path (not just toy
   closures).

Phase 2 (separate PRs, separately tracked):

- **Respawn** — recreate BindingWorker state, re-attach UMEM/XSK
  rings, re-bind queues. State recreation is non-trivial.
- **Sticky-failure detection** — don't infinite-respawn.
- **HA failover trigger** on primary-node worker death.
- **`neigh_monitor_thread` and `local_tunnel_source_loop`
  supervision** — same `catch_unwind` pattern, mechanical, separate
  PRs.

## Honest framing: "detection only"

This PR makes the daemon **detect** dead workers and **report**
them. It does NOT recover forwarding for the dead worker's
bindings, drain its command queue, trigger HA, or restart the
worker. That is Phase 2. Operators learn a worker died via
`cli show chassis forwarding`, then must manually restart the daemon
to recover. This is **better than today** (silent thread death) but
explicitly degraded vs full self-healing.

## Design

### `WorkerRuntimeAtomics` size impact (corrected per Codex Q)

Adding `dead: AtomicBool` to a `#[repr(align(64))]` struct that is
currently exactly 64 bytes (8 × AtomicU64) makes the new size **128
bytes**, not "unchanged" (v1's false claim). The struct-alignment
rounds the total up to the next 64-byte multiple.

Cost: 64 bytes per worker. With typical worker counts (4-12), this
is 256-768 bytes total. Negligible.

```rust
#[repr(align(64))]
pub(crate) struct WorkerRuntimeAtomics {
    // ... existing 8 AtomicU64 ...
    pub tid: AtomicU64,
    /// #925 Phase 1: set to true on caught panic. Once set, never
    /// cleared in this phase. Phase 2 (respawn) will clear on
    /// successful relaunch.
    pub dead: AtomicBool,
    _pad: [u8; 0],
}
```

### Panic message slot

Stored on `Coordinator`, not on the per-worker atomics struct. One
`Arc<Mutex<Option<String>>>` per worker, indexed by `worker_id`.

```rust
// In Coordinator:
worker_panics: Vec<Arc<Mutex<Option<String>>>>,
```

The `Mutex` is fine here because:
- Written exactly once per worker (when the worker dies).
- Read at most once per gRPC status poll (~1 Hz).
- Not on the packet hot path.

### `WorkerRuntimeStatus` additions (Rust + Go)

**Rust** (`userspace-dp/src/protocol.rs`):

```rust
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct WorkerRuntimeStatus {
    // ... existing fields ...
    /// #925: true if the worker thread panicked and was caught.
    #[serde(rename = "dead", default)]
    pub dead: bool,
    /// #925: panic payload string (if any), for operator diagnosis.
    /// Empty string when alive or when the panic payload was not a
    /// string-like type.
    #[serde(rename = "panic_message", default)]
    pub panic_message: String,
}
```

**Go** (`pkg/dataplane/userspace/protocol.go`):

```go
type WorkerRuntimeStatus struct {
    // ... existing fields ...
    Dead         bool   `json:"dead,omitempty"`
    PanicMessage string `json:"panic_message,omitempty"`
}
```

**Display** (`pkg/dataplane/userspace/statusfmt.go:307-329`):

When formatting the worker runtime table, prepend a "DEAD" marker
in the worker column for any worker with `Dead == true`, and emit
the panic message on a follow-up line.

```go
if w.Dead {
    fmt.Fprintf(&b, "  %-6d %-8d   DEAD - panicked: %s\n",
        w.WorkerID, w.TID, w.PanicMessage)
    continue
}
```

### Logging — use `eprintln!`, not slog (corrected per Codex Q)

The codebase has no `slog` dependency. Per `CLAUDE.md`'s logging
rules: `eprintln!("xpf-userspace-dp: ...")` writes to journald via
stderr. A panic is a one-time event, so the eprintln! cadence is
fine.

### Spawn closure rewrite

`userspace-dp/src/afxdp/coordinator.rs:716-748`:

```rust
let panic_slot = Arc::new(Mutex::new(None::<String>));
self.worker_panics.push(panic_slot.clone());
let runtime_atomics_supervisor = runtime_atomics.clone();
let worker_id_supervisor = worker_id;
let join = thread::Builder::new()
    .name(format!("xpf-userspace-worker-{worker_id}"))
    .spawn(move || {
        let result = std::panic::catch_unwind(
            std::panic::AssertUnwindSafe(|| {
                worker_loop(/* same args */);
            }),
        );
        if let Err(payload) = result {
            let msg = panic_payload_message(&payload);
            eprintln!(
                "xpf-userspace-dp: worker_loop panicked (worker_id={}): {}",
                worker_id_supervisor, msg
            );
            // Publish the message via the panic slot. lock() may be
            // poisoned if a future panic on the read side leaves it
            // poisoned; use the same `into_inner` pattern as #949.
            match panic_slot.lock() {
                Ok(mut slot) => *slot = Some(msg),
                Err(poisoned) => *poisoned.into_inner() = Some(msg),
            }
            // Mark dead. Relaxed is fine here — the panic_slot mutex
            // publishes the message; the dead flag is a one-shot
            // diagnostic, not a synchronization barrier.
            runtime_atomics_supervisor
                .dead
                .store(true, Ordering::Relaxed);
        }
    })
    .expect("spawn worker");
```

### `AssertUnwindSafe` rationale (corrected per Codex Q2)

`worker_loop` does NOT take `&mut` parameters; it takes owned
values and `Arc`s. After a panic:

- **Owned values** (BindingPlan, atomics, etc.) are dropped on
  unwind. Caller never observes them again — they were `move`d into
  the closure.
- **`Arc<Mutex<>>` shared state** (sessions, neighbors, etc.) MAY
  become poisoned if `worker_loop` panicked while holding a lock.
  This is acceptable per #949's poison policy: every shared mutex
  read uses `lock().unwrap_or_else(|e| e.into_inner())`, ignoring
  poison. The data may be in a partial-update state, but that's the
  same hazard #949 already accepted.

So `AssertUnwindSafe` is sound here for the specific reason
"poison-tolerant shared state plus owned-value drop", NOT v1's
incorrect "references are dropped" reasoning.

### Shared-state invariant audit (Codex Q3)

`publish_shared_session` updates the primary session map, owner
index, NAT alias map, and forward-wire map in **separate** lock
regions (`shared_ops.rs:620`). A panic between steps could leave
map/index skew. **This pre-exists this PR.** The plan does not
introduce new invariant hazards; it just reports the panic that
caused them. Document this honestly: catching a panic does not
imply recoverable-state semantics.

### `panic_payload_message` helper (corrected per Codex Q6)

```rust
fn panic_payload_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        // Generic fallback. We CANNOT reliably extract a concrete
        // type name from `dyn Any` (type_name_of_val on a Box<dyn>
        // gives the trait object's name, not the inner type), so do
        // not pretend to.
        String::from("non-string panic payload")
    }
}
```

Test for the fallback: panic with `i32`; assert message ==
"non-string panic payload" (NOT v1's false claim of "i32").

## Implementation steps

1. **Rust types**: add `dead: AtomicBool` to `WorkerRuntimeAtomics`
   (`worker_runtime.rs`).
2. **Coordinator**: add `worker_panics: Vec<Arc<Mutex<Option<String>>>>`
   field. Push a slot per worker spawn.
3. **Rust protocol**: add `dead` and `panic_message` to
   `WorkerRuntimeStatus` (`protocol.rs:1043`).
4. **`panic_payload_message`** helper (private, in `coordinator.rs`).
5. **Spawn-closure rewrite** at `coordinator.rs:716` per the
   pseudo-code above.
6. **Update `coordinator.worker_runtime_snapshots()`** at
   `coordinator.rs:1216` to surface `dead` and `panic_message`.
7. **Go protocol**: add `Dead bool` and `PanicMessage string` to
   `WorkerRuntimeStatus` in `pkg/dataplane/userspace/protocol.go:528`.
8. **Go statusfmt**: update `pkg/dataplane/userspace/statusfmt.go:310`
   to show DEAD marker + panic message.
9. **Tests** (see below).

## Tests

### Real spawn-path test (Codex Q9)

The plan adds a `#[cfg(test)]`-only `WorkerCommand::PanicInjection`
variant. Production builds do not include this variant. The test
spawns a worker through the actual `Coordinator::spawn_workers`
path, sends a `PanicInjection` command, joins the thread, and
asserts the dead flag is set + panic message is published via
`worker_runtime_snapshots()`.

```rust
#[cfg(test)]
#[test]
fn worker_panic_is_caught_and_reported() {
    let mut coordinator = Coordinator::new_minimal_for_test();
    coordinator.spawn_workers(/* test config */);
    coordinator.send_command_to_worker(0, WorkerCommand::PanicInjection);
    coordinator.wait_for_worker_dead(0, Duration::from_secs(2));
    let snapshots = coordinator.worker_runtime_snapshots();
    assert!(snapshots[0].dead);
    assert!(snapshots[0].panic_message.contains("PanicInjection"));
}
```

### Unit tests for `panic_payload_message`

```rust
#[test]
fn panic_payload_string_str() {
    let r = std::panic::catch_unwind(|| panic!("hello"));
    let payload = r.unwrap_err();
    assert_eq!(panic_payload_message(&payload), "hello");
}

#[test]
fn panic_payload_string_owned() {
    let r = std::panic::catch_unwind(|| {
        panic!("{}", String::from("world"))
    });
    let payload = r.unwrap_err();
    assert_eq!(panic_payload_message(&payload), "world");
}

#[test]
fn panic_payload_non_string_falls_back() {
    let r = std::panic::catch_unwind(|| panic_any(42_i32));
    let payload = r.unwrap_err();
    assert_eq!(panic_payload_message(&payload), "non-string panic payload");
}
```

(`panic_any` from `std::panic`.)

## Acceptance gates

1. `cargo build --release` clean.
2. `cargo test --release` ≥ 825 + 4 = 829 / 829 pass (3 unit + 1
   integration).
3. Cluster smoke (HARD): no regression — `catch_unwind` is invoked
   ONCE per spawn, not per packet, so cost is 0/packet.
   - iperf-c P=12 ≥ 22 Gb/s
   - iperf-c P=1 ≥ 6 Gb/s
   - iperf-b P=12 ≥ 9.5 Gb/s, 0 retx
4. **Manual injection (recommended, not gated)**: hot-patch a panic
   into `worker_loop` (or use a feature-flagged build), restart the
   daemon, observe `cli show chassis forwarding` showing the worker
   as DEAD with the panic message. Verify the daemon stays up and
   other workers continue.
5. Codex hostile review: AGREE-TO-MERGE.
6. Gemini adversarial review: AGREE-TO-MERGE.

## Risk

**Medium-low.**

- `catch_unwind` semantics are well-understood Rust stdlib.
- `AssertUnwindSafe` rationale is honest (poison-tolerant shared
  state, owned-value drop).
- Wire compat: Go decoder doesn't use `DisallowUnknownFields`;
  unknown fields ignored. `bool::default() = false` and
  `String::default() = ""` are correct sentinels.
- Hot path is unaffected — `catch_unwind` only intercepts
  unwinding, not normal returns. Per-packet cost is zero (the
  wrapper is around `worker_loop()` which runs for the entire
  worker lifetime).

## Out of scope

- Respawn (Phase 2)
- Sticky-failure detection (Phase 3)
- HA failover trigger (Phase 4)
- `neigh_monitor_thread` and `local_tunnel_source_loop` supervision
  (separate PRs, mechanical)
- Production debug `WorkerCommand::PanicInjection` (test-only;
  `#[cfg(test)]`).
- Improving `publish_shared_session` cross-map atomicity (pre-existing
  hazard, separate concern).

These all live under #925 in the issue tracker; this PR is
**Phase 1: catch + report**, the foundation.
