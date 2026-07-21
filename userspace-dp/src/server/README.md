# userspace-dp/src/server/

Control-socket lifecycle and request dispatch. The Go daemon talks to
this surface over a Unix socket using a newline-delimited text protocol.

## Files

- `mod.rs` — module root, public API surface.
- `lifecycle.rs` — `run()` is the daemon entry called from `main.rs`.
  Argv parsing (`--workers N`, `--control-socket PATH`, etc.),
  socket setup (control + a derived dedicated session-install
  socket so session installs don't share the control channel),
  sysctl tuning, signal handling.
  - **Socket-buffer sysctls are raise-only (#2970).** `run()` bumps the
    host-global `rmem_default`/`rmem_max`/`wmem_default`/`wmem_max` to a
    64 MiB target (`SOCKBUF_TARGET`) so AF_XDP copy-mode sockets receive
    at line rate, but it only ever *raises* — `raise_only_value` /
    `raise_sysctl` skip the write when the current value is already
    `>=` target. The target is kept equal to the Go control plane's
    `tuneSocketBuffers` desired (`pkg/dataplane/userspace/process.go`,
    `const desired = 67108864`); the Go side raises these before
    launching the helper, so whichever runs second is a no-op rather
    than a fight. Earlier the helper unconditionally wrote 16 MiB and
    clobbered Go's 64 MiB (and any operator-tuned larger value) back
    down, reintroducing receive drops.
  - **Stale-socket-only unlink guard (#2974).** Before binding the control
    and derived session sockets, `run()` clears any leftover inode via
    `remove_stale_socket`, which `symlink_metadata`-inspects the path and
    removes it ONLY when it is a real Unix socket (a stale socket from a
    prior run — the happy path). A regular file, directory, symlink, or any
    other object at the path is refused with a diagnostic naming the path
    and observed type, and the startup sites propagate that as a bind abort
    — the root helper takes `--control-socket` as an argument, so it must
    fail closed rather than silently delete a wrong path. The shutdown
    cleanup uses the same guard but keeps its best-effort posture: a
    non-socket logs a warning and does not fail shutdown. (`symlink_metadata`
    does not follow symlinks, so a symlink reports as a symlink, not a
    socket, and is left in place.)
- `state.rs` — `ServerState`: coordinator handle, latest config
  snapshot, session-table handle, policy state.
- `handlers/` — request dispatch (`handlers/mod.rs` is the
  `handle_stream` dispatcher). One per-verb file per request kind
  (`apply_snapshot`, `set_forwarding_state`, `set_queue_state`,
  `inject_packet`, `stop_workers`, `rebind`, …).
- `helpers.rs` — shared daemon-loop utilities (`replan_queues`,
  `replan_bindings_from_candidates`, `summarize_queues`, capability
  checks).
  - **`write_state` holds the `ServerState` lock only to snapshot, not to
    persist (#5469).** Persisting the state file used to run
    `refresh_status`, `serde_json::to_vec_pretty` over the whole
    `ProcessStatus` + `ConfigSnapshot`, AND `StateWriter::persist` (file +
    parent-dir fsync) all under the `ServerState` lock. Because the fallback
    session-delta poll sets `persist_state` on every nonempty request, under
    session churn each delta poll serialized+fsynced the full state while
    holding the lock that also gates snapshot apply, status, and HA/control
    ops — a lock convoy. `write_state` now holds the lock ONLY long enough to
    `refresh_status` and clone a minimal owned payload (`build_state_payload`,
    the sole guard-touching half) plus a cheap Arc bump of the writer handle,
    then DROPS the guard before `encode()` (the `to_vec_pretty`) and
    `persist`. All persists still funnel through `StateWriter`'s single writer
    thread and publish via temp+atomic-rename (`finalize_durably`), so
    concurrent lock-free writers never tear the file; semantics are
    last-writer-wins and any transient staleness self-corrects on the next
    periodic write. `write_state_releases_lock_before_persist` is the
    fail-on-revert guard (a same-thread `try_lock` at the persist point, which
    a non-reentrant `Mutex` grants only if the guard was truly dropped).
- `tests.rs` — colocated unit tests for the dispatcher, the per-verb
  handler error/gating arms, and the pure helper predicates (#1653
  §3.1). Handlers are driven through the real `handle_stream` call site
  over a socketpair, so a test fails if the dispatch wiring or
  status-field population regresses (the #1642 drift class).

## Request protocol

Each request is one JSON object per line, response is one JSON object.
The shapes are mirrored in `pkg/dataplane/userspace/protocol.go` on the
Go side; **the JSON tags ARE the contract** — changing one without
updating the other breaks the helper.

`ConfigSnapshot.version` is a compatibility gate, not just documentation.
The helper accepts only the current snapshot protocol version; this prevents a
new daemon from publishing fields such as policy-scheduler inactive bits or
source-NAT persistent-lease settings to a helper that would silently ignore
them.
The helper also reports `config_snapshot_protocol_version` in status so a new
daemon can fail closed before sending snapshots that require newer runtime
semantics to an older helper binary that predates the gate. If the daemon
detects an incompatible helper while scheduled policies or per-pool source-NAT
`persistent-nat` settings are configured, it sends `set_forwarding_state
armed=false` before returning the compile/publish error; the old helper must
not keep forwarding a stale snapshot that ignores those semantics.

`inject_packet_tuple_protocol_version` is the corresponding status gate for
`inject_packet` requests that set `emit_on_wire=true`. Those requests must carry
the complete tuple metadata (`source_ip`, `destination_ip`, protocol, and ports)
on the control wire; helpers reject legacy emit-on-wire requests instead of
synthesizing tuple identity locally.

## Reconciliation

`replan_queues` derives the binding plan from the current
`ConfigSnapshot`: enumerate userspace-binding interfaces, count their
RX queues, and emit one `BindingStatus` per `(queue_id, interface)`
pair. The binding-candidate decision is a single shared invariant
(#2915): `replan_queues`, the plan-key hash
(`update_snapshot_binding_plan_key`), and the Go authoritative allowlist
(`UserspaceBoundLinuxInterfaces` /
`userspaceSkipsIngressInterface`) all filter through the same exclusion
contract — `include_userspace_binding_interface` (zoned, non-tunnel,
non-local-fabric, excluding `fxp*`/`em*`/`fab*`/`lo0` and `mgmt`/`control`
zones). The hash MUST cover exactly the interfaces the planner acts on, so
a change to a non-candidate interface never spuriously bumps the plan key
and a `ge-*`/`xe-*`/`et-*` netdev placed in a mgmt/control/tunnel/fabric
context is never planned as an AF_XDP binding the rest of the system does
not account for.

The same-plan fast path in `apply_snapshot` (`handlers/snapshot.rs`) relies
on this coupling for correctness (#2916): when `snapshot_binding_plan_key` is
unchanged it skips `replan_queues` entirely (it only reconciles/refreshes the
running bindings, never re-deriving the layout). That is sound only because
the hash covers EVERY snapshot-derived field `replan_queues` consumes to build
the layout — the candidate set (shared predicate, above) plus, per candidate,
`linux_name` (bound netdev + dedup key), `ifindex` (per-binding ifindex), and
`rx_queues` (queue count), plus the fabric parents and `workers`/`ring_entries`
/`shared_umem`. Any new field the planner starts reading MUST be folded into
`update_snapshot_binding_plan_key`, or a same-plan refresh will leave a stale
worker layout. `plan_key_covers_every_replan_queues_input` (#2916) pins this:
mutating any planner-consumed field bumps the key (and is shown to change the
produced layout), so a dropped hash field goes RED.

`rx_queues` is folded in via its EFFECTIVE value, not the raw snapshot field
(#3007). When the snapshot carries the degenerate `rx_queues == 0` fallback,
`replan_queues` resolves the real channel count from sysfs
(`rx_queue_count` → `/sys/class/net/<if>/queues`), and THAT count drives the
layout. `effective_rx_queues(snapshot_rx_queues, linux_name)` is the single
resolution path shared by both the planner and the hash, so the dedup key can
never disagree with the layout: a nonzero snapshot never reads sysfs (the key
stays byte-identical to the raw-field hash), while a 0 snapshot folds the
sysfs-resolved count in — so an out-of-band channel change (`ethtool -L <if>
combined N`, no config commit) bumps the key and forces a replan instead of
taking the same-plan-skip. `plan_key_folds_sysfs_resolved_rx_queues_when_snapshot_is_zero`
and `plan_key_for_nonzero_rx_queues_ignores_sysfs` pin both halves.

For an ORPHAN VLAN child — a VLAN unit whose physical parent is NOT itself a
binding candidate — the planner re-keys the child onto its parent netdev and
uses the parent's HARDWARE queue count (`rx_queue_count(parent)`), never the
child's lone software queue (#3091). The plan key must hash the SAME value, so
`plan_key_rx_queues(snapshot, iface, linux_name)` is the single resolution path
for the hash: for the orphan case it returns `rx_queue_count(parent)`, matching
the layout; for the normal VLAN case (parent IS a candidate, child deduped onto
it and covered by the parent's own physical key entry) and physical/non-VLAN
ifaces it returns `effective_rx_queues(...)` exactly as #3007. Before #3175 the
key hashed the child's own software-queue count, so an out-of-band `ethtool -L
<parent> combined N` on the parent of an orphan VLAN child did NOT bump the key
→ same-plan-skip → stale layout. `plan_key_folds_parent_sysfs_queues_for_orphan_vlan_child`
and `plan_key_for_normal_vlan_child_ignores_parent_sysfs` pin the orphan re-key
and the normal-case no-regression.

The Rust planner does:

```rust
binding.worker_id = (queue_id % workers.max(1)) as u32;
```

so modulo assignment can map multiple queues onto the same worker
when `queues > workers`. The Go side's
`pkg/daemon/rss_indirection.go` reshapes RSS indirection only on
**mlx5** drivers and only when `workers > 1 && workers < queues`,
concentrating traffic onto queues `0..workers-1` (it does not change
the Rust planner's `queue_count`). With `workers == 1` it leaves the
live RSS table untouched (single worker drains all queues), and on
non-mlx5 drivers (i40e, etc.) it doesn't reshape at all. The default
RSS table is restored either when the kill switch fires
(`enabled == false`), or via `maybeRestoreDefault()` on the
`workers > 1 && workers >= queues > 1` path — there to undo a
concentrated table left by an earlier `workers < queues`
configuration (#805). On non-mlx5 + `workers > 1 && workers <
queues`, modulo collision can leave one worker bound to multiple
queues. See PR #1243's kill record for why i40e doesn't reshape.

## Gotchas

- `reconcile_status_bindings` has two arms. When `should_run_afxdp`
  holds it runs `Coordinator::reconcile` and returns its
  `Result<(), afxdp::ReconcileError>` (#3789): a pre-teardown abort
  (integrity build fault or a missing / unopenable mandatory pin) surfaces
  as `Err`, and the `apply_snapshot` handler's full-apply /
  same-plan-`needs_reconcile` legs fail closed on it — restoring the prior
  snapshot + status fields and reporting `ok=false` instead of persisting
  the rejected snapshot (see `docs/userspace-dataplane-architecture.md`,
  "Control-plane handler observes the reconcile outcome"). The
  already-accepted-snapshot callers reconcile a registration toggle / rebind
  / forwarding-state change, not a new config, so there is no rejected
  snapshot to un-persist — but the reconcile can still fault (mandatory-pin
  preflight / forwarding-build integrity error). #5621: `set_binding_state`,
  `set_queue_state`, and `rebind` (#6134) — and `set_forwarding_state`
  (#6135, the 4th site #5621 had excluded) — now SURFACE that `Err` (report
  `ok=false` + "`<site> reconcile failed: {err}`", refresh status, and return
  BEFORE `wait_for_binding_settle` / `persist_state=true`) instead of the old
  `let _ = reconcile_status_bindings(..)` discard that acked `ok=true` after a
  failed (re)bind; `rebind::handle` took a `response` parameter for this.
  #4952: the reconcile `Err` now also carries `ReconcileError::WorkerSpawn`
  — the one variant raised AFTER teardown (a `bring_up_workers`
  `spawn_supervised_worker` / `pthread_create` EAGAIN/ENOMEM leaves a queue
  set with no XSK-bound worker). The already-accepted-snapshot callers
  (`set_binding_state` / `set_queue_state` / `rebind` / `set_forwarding_state`)
  already fail closed on ANY `Err`, so they surface it unchanged. The
  `apply_snapshot` full-apply and same-plan-`needs_reconcile` legs SPECIAL-CASE
  it: unlike the pre-teardown integrity/map faults (where the prior workers
  stayed live and restoring `existing_bindings` is truthful), the old workers
  are GONE here — so they report `ok=false` + "`worker spawn failed after
  teardown (...)`", refresh status to the REAL post-teardown per-binding state
  (they do NOT restore `existing_bindings`), roll the in-memory baseline back
  to the prior good snapshot + status generation, and return BEFORE
  `persist_state=true` (the broken snapshot must never become the boot
  baseline). Pre-#4952 `bring_up_workers` returned `()` and swallowed the
  spawn error (overwriting `last_reconcile_stage` with `spawned:..`), so the
  handler acked `ok=true` and persisted a dataplane-down snapshot — a silent
  forwarding outage with no retry. Regression-tested per leg: the
  same-plan-`needs_reconcile` leg by
  `post_teardown_spawn_failure_fails_closed_no_persist_4952`, and the
  full-apply (plan-change) leg by
  `full_apply_post_teardown_spawn_failure_fails_closed_no_persist_6140`
  (#6140 — the full-apply arm was previously covered only transitively).
  #5143: `ReconcileError::WorkerBindIncomplete` is the SECOND post-teardown
  variant — a worker that SPAWNED but whose in-thread XSK/UMEM bind did not
  bring up its full planned queue set (a live-but-unbound worker whose
  heartbeat used to satisfy the supervisor), caught by `bring_up_workers`'
  per-worker startup readiness barrier (HEARTBEAT != READINESS). Both
  `apply_snapshot` legs handle it IDENTICALLY to `WorkerSpawn` (the shared
  `WorkerSpawn(stage) | WorkerBindIncomplete(stage)` arm): `ok=false`, roll
  the in-memory baseline back, refresh status to the REAL post-teardown
  per-binding state, and return BEFORE `persist_state=true`. Only the error
  verb differs — "`worker bind incomplete after teardown (...)`" vs "`worker
  spawn failed after teardown (...)`" — so the #4952/#6140 assertions that
  pin the "worker spawn failed" wording stay green. Regression-tested (full-
  apply leg) by
  `full_apply_post_spawn_inthread_bind_failure_fails_closed_no_persist_5143`.
  When
  `should_run_afxdp` does NOT hold (forwarding disarmed / unsupported) it
  `stop()`s every worker and then routes the per-binding status through
  `refresh_bindings` — which sends each now-workerless slot through
  `zero_unbound_slot`, clearing the FULL survivor set
  (`socket_ifindex`/`socket_queue_id`/`socket_bind_flags`,
  `flow_cache_capacity`, `active_flow_count`, every counter gauge, the
  latency histograms, plus `bound`/`xsk_registered`/`xsk_bind_mode`/
  `zero_copy`/`socket_fd`/`ready`/`last_error`) and rebuilds the CoS
  owner→worker map empty. This is the SAME tail the `no_snapshot`
  reconcile arm runs (#2515). Do NOT replace it with a hand-clear of a
  subset of fields: #2794 was exactly that bug — the disarmed arm left
  `socket_ifindex`/`queue_id`/`bind_flags` + `flow_cache_capacity`/
  `active_flow_count` stale, so `show` reported a disarmed slot as if
  still bound on its old queue.
- `defer_workers=true` requests skip the worker spawn until the next
  reconcile. Used during RETH MAC programming so workers don't bind to
  an interface that's about to drop and re-add its MAC. **The deferred
  apply still runs the pre-teardown integrity build before ack/persist
  (#5171).** Although the spawn is deferred, the snapshot is still ACKed +
  persisted as the boot baseline, so it must be fully buildable with all
  mandatory resources. The defer branch of `handlers/snapshot.rs` calls
  `guard.afxdp.validate_snapshot_buildable(Some(&snapshot))` — the SAME
  policy preflight + mandatory-map openability + full forwarding build
  that `reconcile` runs, factored out side-effect-free — BEFORE the
  side-effecting tunnel/WG prunes and the `guard.snapshot` swap, and fails
  closed on error (restore the bumped status generation/capabilities,
  `ok=false`, no persist), exactly mirroring the #3766/#3789 same-plan
  capture-restore legs. It cannot reuse `reconcile_status_bindings`: with
  forwarding not yet armed (arming follows the deferred bring-up) that
  takes the disarmed STOP path (a teardown with no integrity build), and
  when armed it would spawn workers — both wrong for a deferred apply.
  Pre-#5171 the defer path skipped this build, so a non-buildable config
  (bad interface address / CoS queue / NAT64 / NPTv6 rule, or a
  MISSING/UNOPENABLE mandatory map pin) was acked `ok=true` and persisted
  as the boot baseline, only to fail-OPEN at the later deferred bring-up
  (whose re-apply/rebind failures are warning-only) — a fail-open on a
  security appliance.
- Session installs run on a **dedicated** session-install socket
  (`derive_session_socket_path` next to the control socket), so they
  do not share the control-channel queue with status poll, HA sync,
  snapshot sync, and forwarding sync. The control channel is still
  shared by those other callers; adding a new caller there at >1 Hz
  can still starve the other low-frequency control operations.
