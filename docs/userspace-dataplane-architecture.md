# Userspace AF_XDP Dataplane Architecture

## Overview

The userspace dataplane is a Rust-based packet forwarding engine that
processes transit traffic via AF_XDP sockets, bypassing the kernel
networking stack for stateful firewall processing. Under #1373 it is the
primary/default target for dataplane development and routine validation. It
still runs alongside the legacy BPF XDP pipeline while retirement blockers are
closed.

This document tracks the current `master` architecture. It is not a claim
that every supported configuration already reaches feature or performance
parity with the legacy eBPF dataplane. For the exact admission gate, use
[`userspace-dataplane-gaps.md`](userspace-dataplane-gaps.md). For active
debugging entry points, use [`userspace-debug-map.md`](userspace-debug-map.md).

```
                        ┌─────────────────────────────────┐
                        │          xpfd (Go)             │
                        │  ┌───────────┐  ┌────────────┐  │
                        │  │  Config   │  │  Cluster    │  │
                        │  │  Store    │  │  Sync       │  │
                        │  └─────┬─────┘  └──────┬─────┘  │
                        │        │               │         │
                        │  ┌─────▼───────────────▼─────┐  │
                        │  │  Userspace Manager         │  │
                        │  │  (snapshot, lifecycle)      │  │
                        │  └─────┬─────────────────────┘  │
                        └────────┼────────────────────────┘
                    Unix socket  │  (JSON control protocol)
                        ┌────────▼────────────────────────┐
                        │  xpf-userspace-dp (Rust)       │
                        │  ┌────────┐ ┌────────┐          │
                        │  │Worker 0│ │Worker 1│ ...      │
                        │  │ AF_XDP │ │ AF_XDP │          │
                        │  └───┬────┘ └───┬────┘          │
                        └──────┼──────────┼───────────────┘
                               │          │
                    ┌──────────▼──────────▼──────────┐
                    │       Kernel (mlx5 driver)      │
                    │  ┌──────────────────────────┐   │
                    │  │  XDP Shim (BPF program)   │   │
                    │  │  redirect → XSK socket    │   │
                    │  └──────────────────────────┘   │
                    │  ┌──────┐  ┌──────┐             │
                    │  │ NIC  │  │ NIC  │  25G mlx5   │
                    │  │ LAN  │  │ WAN  │  ConnectX-5  │
                    │  └──────┘  └──────┘             │
                    └─────────────────────────────────┘
```

## Component Architecture

### 0. Operator Buffer Telemetry

`show system buffers` and REST `/api/v1/system/buffers` use the userspace
helper status path when the active dataplane implements
`Status() (userspace.ProcessStatus, error)`; they do not depend on BPF map
occupancy for userspace mode. The rendered rows are aggregate AF_XDP UMEM
frame, TX-ring, session-table, and flow-cache utilization, with `WARNING` at
>=80% and `CRITICAL` at >=90%, plus the same dynamic userspace status
counters. `show system buffers detail` adds per-binding rows after the
aggregates so a hot binding is visible even when total aggregate usage is low.
Both userspace buffer commands preserve the legacy `Active sessions` footer.

The bounded source fields are
`ProcessStatus.PerBinding[].umem_total_frames`,
`umem_inflight_frames`, `tx_ring_capacity`, and `outstanding_tx`; the
same fields on `ProcessStatus.Bindings[]` are accepted as a fallback for
older helper status snapshots. If neither path publishes capacity, the
CLI reports the missing status fields rather than showing BPF-map
metrics for userspace buffers.

CoS queued-byte rows use `ProcessStatus.CoSInterfaces[].Queues[]`
`buffer_bytes` and `queued_bytes`. Session-table rows use
`session_table_entries/max_sessions`, and flow-cache rows use helper-published
`flow_cache_capacity`. Neighbor-cache entries, flow-cache collision evictions,
and worker queue pressure stay in the status-counter section unless Rust owns
and publishes a bounded capacity denominator. Go must not infer missing
denominators from Rust private constants.

### 1. XDP Shim (`userspace-xdp/src/lib.rs`)

A minimal BPF program attached at the NIC driver level that decides
whether each packet should be processed by userspace or the existing
kernel BPF pipeline.

**Packet decision flow:**

```
Packet arrives at NIC
  │
  ├─ Non-IP (ARP, etc.) ──────────────────► kernel stack
  ├─ Multicast / broadcast ────────────────► cpumap → kernel stack
  ├─ Local destination ────────────────────► cpumap → kernel stack
  ├─ GRE / ESP live exceptions ────────────► cpumap → kernel stack
  ├─ Degraded local/control cases ─────────► kernel stack
  ├─ Degraded transit cases ───────────────► XDP_DROP
  │
  ├─ Has active session in BPF map? ───YES─► XDP_REDIRECT → XSK socket
  │
  ├─ Session miss but still transit traffic ─► XDP_REDIRECT → XSK socket
  │
  └─ Binding/heartbeat failure on DP-managed interface ─► local/control pass or transit drop
```

**Key design decisions:**

- **Session-aware, not session-only redirect**: live sessions skip extra
  local/interface-NAT checks, but transit session misses are still redirected
  so the Rust dataplane can perform first-packet policy/NAT/FIB evaluation.

- **cpumap for kernel delivery**: For IP packets that must reach the kernel,
  the shim uses `bpf_redirect_map` to a cpumap when available so zero-copy
  XSK frames are released before stack delivery. Direct `XDP_PASS` is reserved
  for cases such as ARP/NDP where cpumap delivery does not update the kernel
  neighbor state correctly.

- **Fail closed on dead bindings**: if a binding is missing, not ready, or
  its heartbeat is stale on a userspace-managed interface, the shim passes
  only proven local/control traffic to the kernel. Non-local transit drops in
  compat and strict modes and increments the `transit_drop` degraded-path
  counter. Go exposes the per-reason map as `degraded_path_counters`; the
  pinned BPF map keeps the internal compatibility name
  `userspace_fallback_stats` until the mixed-version boundary is retired. The
  map is a **per-CPU** array (`#4113`) — native XDP increments it per RX-queue
  CPU with a non-atomic RMW, so shared storage would drop counts under load;
  the Go/helper readers sum across CPUs. The userspace runtime does not require
  the legacy `xdp_main_prog` fallback path.

- **Heartbeat watchdog**: Each worker writes a timestamp to a BPF array
  map every 250ms. The shim checks freshness (5s timeout) and refuses
  to redirect if the worker appears stalled.

### 2. Rust Dataplane Process (`userspace-dp/`)

The main forwarding engine. Spawned by xpfd as a child process,
communicates over a Unix domain socket.

#### Process Structure

```
main thread
  ├── Control socket listener (JSON protocol)
  ├── Coordinator (manages workers and state)
  │
  ├── Worker 0 ──► AF_XDP binding (ge-0-0-1, queue 0)
  │                AF_XDP binding (ge-0-0-2, queue 0)
  │
  ├── Worker 1 ──► AF_XDP binding (ge-0-0-1, queue 1)
  │                AF_XDP binding (ge-0-0-2, queue 1)
  │
  ├── ... (one worker per RSS queue)
  │
  ├── Sync thread (session delta export)
  └── io_uring thread (state file persistence)
```

Each worker thread is pinned to a CPU and processes all packets from
its assigned RSS queues. Workers are independent — no locks on the
forwarding hot path.

#### State-file persistence: crash-safe atomic writes (`state_writer.rs`)

The io_uring state-persistence thread (`src/state_writer.rs`) writes each
state snapshot via write-temp-then-rename with a full durability contract
(`finalize_durably`): fsync the temp file, atomic `rename` onto the
destination, then fsync the parent directory so the rename survives power
loss. Each write uses a **private** temp path
`<dest>.<pid>_<starttime>.<seq>.tmp` created `O_EXCL`, so two concurrent
writers — including a replacement helper racing the old one during a
restart/upgrade handover — can never open/truncate/write the SAME temp
and publish crossed bytes (#2705). The `<pid>_<starttime>` component is
the writer's *process-instance* identity (pid + process start time from
`/proc/<pid>/stat` field 22).

Because the temp is unique per write, a crash between create and rename
leaks one orphan temp. To bound that (#2714), the writer runs a
best-effort **orphan sweep once per distinct destination** at the first
write to it: it removes only siblings matching
`<dest>.<pid>_<starttime>.<seq>.tmp` whose embedded writer *instance* is
no longer live. Liveness is keyed on the **pid AND its process start
time**, not the bare pid (#2957): pids are recycled after a crash, so a
bare-pid `/proc/<pid>` check would preserve a dead writer's orphan
forever once Linux reassigns that pid to an unrelated process, pinning
crash debris indefinitely. The sweep instead reads the candidate pid's
current start time and preserves the temp only when both the pid exists
and its start time matches the embedded one — so a reused pid (different
start time) is correctly swept while a genuinely-live writer's in-flight
temp is never deleted (preserving the #2705 guarantee). The sweep is
fail-safe — any error is swallowed so a sweep failure can never break the
subsequent write.

#### Reconcile Ordering Invariant (#2440 / #2444 / #2484)

`Coordinator::reconcile` (`coordinator/reconcile/mod.rs`) applies a new
config snapshot in phases: preflight → teardown → reset → apply/publish
→ bringup. The load-bearing invariant is **fail-closed ordering of the
mandatory BPF map FDs**:

- The mandatory map pins — `xsk`, `heartbeat`, `sessions` — are the real
  correctness boundary: a worker cannot serve traffic without them. They
  are opened in `snapshot::preflight_map_fds` **before** `tear_down`
  stops the running workers and **before** `apply_snapshot` publishes a
  newer forwarding view (`coord.forwarding`, the published `ha.runtime`
  `RuntimeView`, `ha.fabrics`) or advances
  `validation.snapshot_installed` / `config_generation`.
- If any mandatory pin is missing or its FD fails to open, the reconcile
  aborts in the preflight: it sets the typed `last_reconcile_stage`
  (`ReconcileStage::MissingPin` / `OpenMapFailed`, #6244) +
  per-registered-binding `last_error`, and returns **without** tearing
  down the prior workers or publishing a newer generation. The previous
  (stale-but-correct) forwarding generation stays published and the
  prior workers keep running.
- The optional maps (conntrack v4/v6, dnat tables) are opened in the same
  preflight with an **empty-vs-present** discipline (codex review-033
  finding 033-23, #2444). The pin string IS the "feature configured"
  signal:
  - An **empty** pin means the feature is genuinely absent — the common
    case, since many deploys carry no conntrack/dnat pins. It yields
    `None` silently and never gates the reconcile (the anti-over-gate
    case).
  - A **present** pin that fails to open means the feature WAS configured
    but its map is unopenable (permission / pin mismatch / corruption).
    That is fatal: it aborts the reconcile via the same fail-closed path
    as a mandatory map (`open_<map>_map_failed:<err>` stage +
    per-binding `last_error`, return before teardown/publish). Running
    degraded would otherwise silently lose session zone/interface
    visibility (conntrack) or break embedded-ICMP NAT reversal —
    PMTUD/traceroute breakage (dnat) — with no readiness signal.
- The **full forwarding-state build** runs in the same preflight, also
  **before** `tear_down` (#2484). The top-of-reconcile policy preflight
  only parses the policy/address-book state, so snapshot INTEGRITY faults
  reachable only inside the full build — `Nptv6UnparseableRule`, NPTv6
  overlap / unresolvable-zone integrity faults from
  `build_forwarding_state_with_policy_counters_and_previous` (NAT64 is
  fail-scoped per #3888 and no longer aborts) — used to
  surface *inside* `apply_snapshot`, after teardown had already stopped the
  workers and reset `coord.validation` / the published view. They are now
  detected by `snapshot::build_reconcile_forwarding` in the preflight: on
  an integrity `Err` the reconcile sets
  `last_reconcile_stage = ReconcileStage::SnapshotIntegrityError` (which
  renders `"snapshot_integrity_error"` byte-for-byte, #6244) and aborts before
  teardown/publish, so the prior generation + workers stay live. The built
  state is stashed on `ReconcileSnapshotFds::forwarding` and **reused** by
  `apply_snapshot` (build-once — no second build on the success path, and
  no double-insert of per-rule counter handles into the live counter
  stores). The build reads `Some(&coord.forwarding)` as its "previous"
  arg, which `tear_down` defaults to empty — another reason it MUST run
  before teardown.
- Only once all mandatory FDs, every present-and-configured optional FD,
  **and** the integrity-validated forwarding state are in hand does the
  orchestrator tear down + rebuild + publish. This completes the
  "all mandatory validation before teardown/publish" invariant across the
  #2440 (map-FD) / #2444 (optional-map) / #2484 (snapshot-integrity)
  trilogy.

This closes a fail-open partial-apply window (codex review-033 finding
033-01): previously the FD open happened *after* teardown + publish, so
a snapshot with an unopenable required pin tore down the workers,
published a newer generation, then aborted bring-up — leaving the helper
advertising a data-plane view backed by no running workers. On a
security appliance that is fail-open. Finding 033-23 (#2444) extended the
same fail-closed treatment to a present-but-unopenable optional map (the
prior `.ok()` swallowed the error and ran degraded). #2484 closed the last
window — a snapshot-integrity fault detected only inside the full
forwarding build, which previously surfaced *after* teardown. Regression
coverage lives in `coordinator/tests.rs`
(`reconcile_mandatory_map_open_failure_keeps_prior_generation_published`,
`reconcile_missing_session_pin_keeps_prior_generation_published`,
`reconcile_all_mandatory_maps_open_advances_published_generation`;
optional-map: `reconcile_present_conntrack_pin_open_failure_keeps_prior_generation`,
`reconcile_present_dnat_pin_open_failure_keeps_prior_generation`,
`reconcile_empty_optional_pins_advance_published_generation` — the
anti-over-gate control —, and
`reconcile_present_optional_pins_open_ok_advance_generation`;
snapshot-integrity:
`reconcile_snapshot_integrity_error_preserves_prior_generation_and_state`,
which seeds a prior generation + a sentinel live worker, feeds a
NAT64-unparseable rule, and asserts BOTH the prior generation and the
prior worker survive — fail-on-revert: moving the integrity build back
inside `apply_snapshot` post-teardown makes the preservation assertions
fail) using the `bpf_map::pin` sentinel-path test seam
(`TEST_MAP_PIN_OK` / `TEST_MAP_PIN_FAIL`) so the ordering is exercised
without real bpffs pins.

##### Control-plane handler observes the reconcile outcome (#3789)

The invariants above keep the *data plane* fail-closed: on a pre-teardown
abort the prior workers + forwarding + published generation stay live. But
`Coordinator::reconcile` returned `()`, so the control-socket
`apply_snapshot` handler could not tell an aborted reconcile from a
successful one. On the two legs that drive the FULL reconcile —

- the **non-same-plan full-apply** branch
  (`server/handlers/snapshot.rs`), and
- the **same-plan `needs_reconcile`** branch (deferred-binding
  reconcile after a `defer_workers` clear) —

the handler stored the incoming snapshot as the boot baseline, set
`persist_state`, and acked `ok=true` regardless of whether the reconcile
actually applied it. A snapshot that passed the policy preflight but
aborted the reconcile (a non-policy integrity build fault, or a missing /
unopenable mandatory pin) was therefore **persisted as a rejected boot
baseline and acked positive** — the M1 class #3766 fixed only for the
same-plan *refresh* leg (`refresh_runtime_snapshot`).

#3789 closes this: `reconcile` (and the `reconcile_status_bindings`
helper) now return `Result<(), ReconcileError>`
(`coordinator/reconcile/mod.rs`), where `ReconcileError::Integrity`
carries the `SnapshotIntegrityError` from the policy preflight or
`build_reconcile_forwarding`, and `ReconcileError::MapSetup` carries the
typed `ReconcileStage` failure identity for a mandatory-pin abort (#6244;
was a cloned `last_reconcile_stage` string). Both
handler legs now mirror #3766's pattern: install the new snapshot for the
reconcile, and on `Err` **restore** the prior snapshot (+ the full-apply
leg also restores `status.bindings`) and the bumped status-reporting
fields (`last_snapshot_generation` / `last_fib_generation` /
`last_snapshot_at` / `capabilities`), report `ok=false`, and do NOT set
`persist_state`. Because the reconcile aborts *before* teardown, the
restore is a status/bookkeeping rollback — the data plane never moved.

The sibling control-socket handlers reconcile the ALREADY-accepted stored
snapshot (a registration toggle / rebind / forwarding-state change, not a
new config), so there is no rejected snapshot to un-persist. But
`reconcile_status_bindings` can still return `Err` even for an accepted
snapshot — the mandatory-pin preflight can fault, or the forwarding build
can hit a non-policy integrity error. #5621 stops `set_binding_state`,
`set_queue_state`, and `rebind` (#6134) — plus `set_forwarding_state`
(#6135, the 4th site #5621 had excluded) — from **discarding** that `Err`:
on failure they report `ok=false` + "`<site> reconcile failed: {err}`",
refresh status, and return BEFORE `wait_for_binding_settle` /
`persist_state=true`, so the control-socket caller no longer mistakes a
failed (re)bind / forwarding reconcile for success (previously the
`let _ = reconcile_status_bindings(..)` discard acked `ok=true` regardless).
`rebind::handle` gained a `response` parameter to carry the error;
`set_forwarding_state`'s `set` already had one. Note the arm=false (disarm)
path still succeeds — `reconcile_status_bindings` takes the disarmed `Ok`
teardown arm — so only an arm reconcile can surface an `Err` here.

Regression coverage: `coordinator/tests.rs`
(`reconcile_build_failure_returns_integrity_err_and_keeps_prior_generation_3789`,
`reconcile_missing_pin_returns_map_setup_err_3789` — the reconcile now
returns the typed error) and `server/tests.rs`
(`apply_snapshot_full_reconcile_build_failure_rejects_and_keeps_prior_3789`,
`apply_snapshot_same_plan_needs_reconcile_build_failure_rejects_and_keeps_prior_3789`
— fail-on-revert: reverting the handler to ignore the reconcile result
makes `ok=false` / prior-snapshot-kept assertions flip). The
`main_tests.rs`
`apply_snapshot_same_plan_clearing_defer_workers_reconcile_abort_fails_closed_3789`
test (renamed from `…_reconciles_bindings`, which previously codified the
swallow) now asserts the deferred-binding reconcile is triggered but the
missing-pin abort fails closed. The #5621 sibling-handler coverage lives in
`server/tests.rs`
(`set_binding_state_failed_reconcile_reports_error_5621`,
`set_queue_state_failed_reconcile_reports_error_5621`,
`rebind_failed_reconcile_reports_error_5621`, and
`set_forwarding_state_failed_reconcile_reports_error_6135` — each faults the
reconcile with a stored `/33`-address snapshot and pins `ok=false`; reverting
the matching handler to `let _ = reconcile_status_bindings(..)` flips exactly
its assertion RED).

#### Per-Packet Processing Pipeline

```
RX from AF_XDP ring (up to 256 frames per batch, 4 batches per poll)
  │
  ├─ Parse XDP metadata (magic, version, 5-tuple, offsets)
  ├─ Validate config/FIB generation (stale → exception)
  │
  ├─ Session lookup (FxHashMap, O(1))
  │   ├─ HIT: Use cached forwarding decision
  │   ├─ SHARED HIT: Promote from shared table (HA peer)
  │   ├─ NAT REVERSE: Repair reply path from forward entry
  │   └─ MISS: Full policy + NAT + FIB evaluation
  │
  ├─ For session miss:
  │   ├─ Zone pair determination (ingress → egress zone)
  │   ├─ Policy evaluation (ordered rule match)
  │   │   └─ Deny → recycle frame, continue
  │   ├─ NAT matching (SNAT rules by zone/prefix)
  │   ├─ FIB resolution (route + neighbor + VLAN)
  │   └─ Install session (forward entry + NAT reverse index)
  │
  ├─ HA enforcement
  │   ├─ Check RG active status
  │   ├─ Watchdog timestamp freshness
  │   └─ Fabric redirect if needed
  │
  ├─ Apply NAT rewrite (incremental L3/L4 checksum)
  ├─ Build egress frame (MAC rewrite, VLAN tag)
  │
  └─ TX submission
      ├─ Same binding: in-place UMEM rewrite when possible
      └─ Cross binding: copy into target binding UMEM on the common path
```

#### Neighbor Resolution — the negative cache does not stop resolution (N1)

A `MissingNeighbor` packet buffers ONE representative per
`(egress_ifindex, next_hop)` in the per-binding `pending_neigh` map
(#1771 §2.2; same-key siblings are recycled — `pending_neigh_admission`
in `neighbor_dispatch.rs`). A hop that never resolves within the pending
timeout is negatively cached for 3 s (`neg_neigh.rs`), and subsequent
cold packets to it fast-fail at the buffer site.

`pending_neigh_admission` returns one of three outcomes, each counted
separately so an operator can tell normal cold-start coalescing from an
exhaustion/attack mode (`record_pending_neigh_admission_drop`,
`neighbor_dispatch.rs`):

- **Buffer** — key absent, room available: this becomes the
  representative driving the probe/dwell clock (no drop counter).
- **DuplicateDrop** (`pending_neigh_duplicate_drops_total`) — the key is
  already pending: normal cold-start sibling coalescing (the first
  packet already drove the kernel probe).
- **CapacityDrop** (`pending_neigh_capacity_drops_total`, #2375) — a NEW
  distinct `(egress_ifindex, next_hop)` refused because the map is at
  `MAX_PENDING_NEIGH` (4096) distinct unresolved hops: distinct-hop
  neighbor exhaustion — the scan / upstream-outage failure mode. Before
  #2375 this case was silent (`CapacityDrop => {}`, counted nowhere);
  exposing it lets operators distinguish "a packet is already probing
  this destination" (duplicate) from "the worker is refusing NEW
  unresolved destinations" (capacity). The refused frame is recycled
  exactly like the duplicate case.

**Pairing contract (#1902, sibling of #1885/#1873):** an entry's
`desc`/`meta`/`decision` must all describe the SAME UMEM frame, because
`retry_pending_neigh` resumes the flow via an in-place UMEM rewrite +
TX. Admission therefore refuses (counts
`pending_neigh_decap_drops_total`, recycles) any GRE-DECAPPED packet —
its `desc` still references the un-decapped OUTER frame while
`meta`/`decision` describe the synthetic INNER frame, so a buffered
entry would retry-TX a mis-rewritten outer packet toward the inner
next-hop. Tunnel-MARKED (encap-bound) decisions are likewise excluded
(#1873 R-E: the retry cannot encapsulate, so the inner packet would TX
plaintext). In both cases the kernel probe has already fired and the
trailing decap-aware slow-path chokepoint (#1901) handles first-packet
delivery; the flow recovers normally once the neighbor resolves.

**Invariant N1 (#1771 §2.4):** while a key is negatively cached, the
shared on-demand resolver (`neighbor_resolver.rs`, #1769) continues to
issue rate-limited single-key RTM_GETNEIGH probes for it — the negative
cache drops *duplicate buffered packets*, never *resolution*. Every
fast-fail enqueues the key to the resolver; the per-key backoff window
(1 s) is strictly shorter than the negative TTL (3 s, pinned by a
compile-time assert), so at least one backoff GET fires inside every
negative window and a recovered host is re-learned instead of
blackholing in 3 s cycles. Pinned by
`invariant_n1_negative_cache_does_not_stop_resolution` (live resolver
thread) plus the admission unit tests.

Observability (#1771 §2.6, all in the status JSON → Prometheus):
`neighbor_resolver_get_backoff_attempts_total` (backoff retries — N1's
"resolution continued" signal), `neighbor_pending_keys` /
`neg_neigh_keys` (current distinct parked / negatively-cached keys,
summed per binding at the ~65 ms debug tick), and the §2.5 monitor
self-heal counters `neighbor_netlink_enobufs_total` /
`neighbor_netlink_redumps_total` / `neighbor_netlink_redump_upserts_total`
(lost-multicast detection → throttled upsert-only re-dump → entries
actually re-added).

#### AF_XDP Ring Management

Each binding manages four rings:

```
┌─────────────┐     ┌─────────────┐
│  Fill Ring   │◄────│  Free Pool  │  Userspace → Kernel
│ (empty bufs)│     │  (recycled  │  "Here are empty frames
└──────┬──────┘     │   frames)   │   for you to fill"
       │            └─────────────┘
       ▼
┌─────────────┐
│  RX Ring     │  Kernel → Userspace
│ (received)  │  "Here are received packets"
└──────┬──────┘
       │ process + rewrite
       ▼
┌─────────────┐
│  TX Ring     │  Userspace → Kernel
│ (to send)   │  "Please transmit these"
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Completion   │  Kernel → Userspace
│   Ring       │  "These TX frames are done,
└─────────────┘   you can reuse them"
```

**Frame lifecycle:**
1. Allocate UMEM frames at startup (ring_entries × 4096 bytes each)
2. Submit empty frames to fill ring
3. Kernel fills frames with received packets, posts to RX ring
4. Worker reads RX, processes, rewrites in-place or copies to TX
5. Submit to TX ring, kernel transmits
6. Completion ring returns transmitted frame offsets
7. Recycle completed frames back to fill ring

**Zero-copy vs copy mode:**
- Zero-copy: NIC DMA writes directly into UMEM. No kernel memcpy.
  Requires driver support and safe kernel-pass handling.
- Copy mode: Kernel copies packet data into UMEM. The current tree still
  contains mlx5/copy-mode mitigations and debugging around fill-ring pressure,
  so do not read "AF_XDP" as meaning "always zero-copy" on current `master`.

#### VLAN unit AF_XDP binding target: the parent-netdev SSOT (#2917)

AF_XDP binds a socket to a netdev's **hardware RX queues**. A VLAN
sub-interface (`reth0.80` → Linux netdev `ge-0-0-2.80`) is a *software*
netdev with no hardware queues of its own — its VLAN-tagged frames are
delivered on the **physical parent's** hardware queues (`ge-0-0-2`, e.g. 6
queues on an mlx5 VF) and the kernel demuxes the tag. Zero-copy AF_XDP for
a VLAN unit therefore **MUST bind the parent physical netdev**; binding the
`.80` unit netdev would fail (or fall back to copy/generic) and, in the
queue planner, collapse the per-interface `queue_count` min to the child's
lone software queue → a single worker (the #3091 ~6 Gbps regression).

This is a single contract enforced on **both** planes from one rule:

- **Rust planner** (`replan_queues` / `vlan_child_parent_netdev`,
  `userspace-dp/src/server/helpers.rs`): a VLAN child (`vlan_id != 0`, a
  non-empty `parent_linux_name` that differs from the row's own netdev) is
  deduped onto its parent — skipped when the parent is itself a candidate
  (the parent's per-queue XSKs already capture the tagged frames), else
  re-keyed onto the parent using the parent's *hardware* queue count
  (#3175). A physical interface or non-VLAN unit binds its own netdev.
- **Go control plane** (`userspaceBindTargetNetdev` →
  `UserspaceBoundLinuxInterfaces`, `pkg/dataplane/userspace/interfaces.go`):
  mirrors the same rule exactly so the D3/RSS allowlist, XDP steering, and
  shim maps all target the parent netdev the planner binds. The allowlist
  never contains a VLAN-suffixed unit netdev.

Cross-plane parity is guarded by `replan_queues_binds_vlan_unit_on_parent_netdev`
(Rust, `main_tests.rs`) and `TestUserspaceBoundLinuxInterfaces_VLANUnitBindsParent`
+ `TestUserspaceBoundLinuxInterfaces_MatchesBindTargetSSOT` (Go,
`snapshot_allowlist_test.go`). Changing one plane's rule without the other
turns these RED.

#### Session Table (`session.rs`)

Per-worker hash table using a SEEDED `FxHasher` (`FxSeededState`, fast
non-cryptographic hash keyed by a per-boot secret).

> **Hot-path hash hardening (#2364).** The node-local hot-path hashes
> that key on attacker-controllable values — the session indices
> (`SessionKey`-keyed `key_to_handle` / `nat_reverse_index` /
> `forward_wire_index` / `reverse_translated_index`, plus the per-IP
> `session_limit_{src,dst}_counts`), the flow-cache set index
> (`FlowCache::set_index`), the fabric queue hash
> (`worker::fabric_queue_hash`), and the screen SYN/ICMP/UDP-flood
> per-source/per-destination count-min sketch cell index
> (`SynRateSketch::cell_index` / `cell_index_ip_port`, #4382) — fold in a
> per-process secret seed
> (`crate::hot_hash_seed::hot_path_hash_seed`, drawn once at first use via
> the same `getrandom(2)` + CLOCK_MONOTONIC/pid/stack fallback +
> never-zero path that backs the CoS SFQ seed). The seed is:
> per-boot random (defeats offline collision construction — an off-box
> sender can no longer precompute keys that thrash one flow-cache set,
> chain a session-map bucket, or pin attack flows onto one fabric worker),
> stable for the process lifetime (so a flow's set/bucket/fabric-queue is
> consistent across its life — caches/maps and fragment ordering keep
> working), and NODE-LOCAL ONLY. The seed is never part of any wire
> protocol or HA-synced structure: HA session sync transmits the explicit
> `SessionKey`, never a hash value, so peers re-bucket under their own
> seed; the fabric queue hash selects among THIS node's local fabric
> egress bindings, so the peer does not need to agree. Hashes that
> require cross-node or cross-restart determinism are therefore deliberately
> **excluded** from seeding (none of the seeded sites have that
> requirement). `owner_rg_sessions` (keyed by `i32` RG/ifindex with inner
> sets of internally allocated `u32` handles) stays on the unseeded
> `FxHasher` — neither key class is an off-box attacker surface. Cost is
> one extra seed word per hasher; no per-packet allocation.

```
SessionKey {
    addr_family: u8,     // AF_INET or AF_INET6
    protocol: u8,        // TCP=6, UDP=17, ICMP=1
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
}
    │
    ▼
SessionEntry {
    decision: SessionDecision {
        resolution: ForwardingResolution {
            disposition,     // ForwardCandidate, LocalDelivery, etc.
            egress_ifindex,
            tx_ifindex,
            neighbor_mac,
            src_mac,
            tx_vlan_id,
        },
        nat: NatDecision {
            rewrite_src,     // Option<(IpAddr, u16)>
            rewrite_dst,     // Option<(IpAddr, u16)>
        },
    },
    metadata: SessionMetadata {
        ingress_zone,
        egress_zone,
        owner_rg_id,
        is_reverse,
        synced,              // true = from HA peer
    },
    last_seen_ns: u64,
    closing: bool,           // FIN/RST received
}
```

**NAT reverse index:** A secondary index maps reply 5-tuples to their
forward session keys. When a reply packet arrives (e.g., from a SNAT'd
connection), the reverse index resolves the original session without
full table scan.

The index is a **1:N multimap** (`nat_reverse_index: reverse-key →
`SmallVec<[handle; 2]>`, #4399). NAT is not always bijective: interface-mode
SNAT with no port translation, DNAT-to-shared-backend, NAT64, and
non-bijective static NAT can map two distinct forward sessions to the SAME
external reverse tuple (the #1758 latent collision; pool-mode SNAT is immune
because PAT makes it bijective). Before #4399 the index stored one handle
per key, so a colliding install DISPLACED the earlier session — its reply
was mis-delivered to the wrong internal host, or dropped once the displacing
session closed and the key was wiped. Now both colliding handles coexist in
the bucket, `find_forward_nat_match` walks the candidates and returns the
first whose forward session reverse-maps to THIS exact reply
(validate-on-lookup), and delete removes only the closing session's handle
(the key is dropped only when its bucket empties). The common,
non-colliding case is a length-1 bucket held inline in the `SmallVec` — one
validate, zero heap — so the pool-mode-SNAT fast path is unchanged. The
`nat_reverse_key_collisions` telemetry counter (published per worker) still
bumps whenever a bucket grows past one handle, quantifying how often the
collision path is exercised.

**All three NAT session indexes are 1:N (#4438).** #4399 fixed only
`nat_reverse_index`; the other two secondary indexes — `forward_wire_index`
(forward-wire-tuple → forward handle, used by `find_forward_wire_match`) and
`reverse_translated_index` (translated/alias-tuple → reverse handle, the alias
branch of `lookup`) — still stored one handle per key and DISPLACED on the same
non-bijective collision, re-opening the exact hijack on the forward and
translated-lookup paths (interface-mode SNAT collapses the forward-wire tuple
just as it collapses the reverse-wire tuple, and DNAT-to-shared-backend / NAT64
collapse two reverse entries onto one translated tuple). #4438 makes both
multimaps with the identical discipline: a shared `NatIndexBucket =
SmallVec<[handle; 2]>`, append-not-displace on install (`nat_index_bucket_push`,
dedup on the per-packet refresh), validate-each-candidate-against-the-full-tuple
on lookup (`find_forward_wire_match_with_origin` and
`resolve_reverse_translated_handle` walk the bucket), and per-handle delete that
drops the key only when its bucket empties (`nat_index_bucket_remove`). Pool-mode
SNAT stays a length-1 inline bucket on every index (zero heap, one validate).
The `nat_reverse_key_collisions` counter now aggregates bucket-growth across all
three indexes; because one non-bijective flow-pair collides on several indexes
at once, it can bump more than once per pair — reinforcing its documented
upper-bound, not-a-pair-census character.

**Protocol timeouts:**
| Protocol | Active | Closing (FIN/RST) |
|----------|--------|-------------------|
| TCP      | 300s   | 30s               |
| UDP      | 60s    | —                 |
| ICMP     | 15s    | —                 |
| Other    | 30s    | —                 |

#### NAT (`nat.rs`)

Stateless per-packet NAT rewrite. Session table holds the NAT decision;
the NAT module applies it:

- **SNAT (interface mode):** Rewrite source IP to egress interface address.
  Source port preserved.
- **SNAT (pool mode):** Rewrite source IP to a configured source pool address
  and allocate a source port from the pool range. For an ICMP/ICMPv6 echo or
  query message the 16-bit **Query Identifier** plays the role of the L4 port
  (RFC 5508 §3.1 "ICMP Query Mappings"): the flow parser lifts it into the
  tuple `src_port` slot, so pool mode allocates a unique translated identifier
  from the same pool id space, rewrites the ICMP Identifier field, and repairs
  the ICMP checksum incrementally (`apply_nat_icmp_identifier_rewrite`,
  #4074). This lets many internal hosts pinging one target with the same id
  share a single pool address without colliding on the reverse tuple
  `(pool_addr, id)`; the reverse companion session and the reply un-NAT are
  keyed on the translated id. Whether a tuple is an ICMP query is decided by an
  authoritative "identifier present" signal threaded from the frame parser
  (`match_source_nat_result_for_tuple`'s `icmp_identifier_present` arg), NOT by
  `src_port != 0` — a SessionFlow is only built for an ICMP protocol when the
  parser matched an identifier-bearing query type, so an ICMP Query Identifier
  of **0** (a valid on-wire value, 0..=65535) is translated like any other id
  rather than misread as flowless (#4088; the earlier `src_port != 0` gate left
  id==0 colliding on `(pool_addr, 0)`). A non-identifier ICMP control/error
  message parses flowless (no SessionFlow, `icmp_identifier_present` false) and,
  like a genuinely port-less protocol (GRE/ESP/AH/OSPF), takes the address-only
  path — its L4 bytes are never rewritten. A genuine IPv4 **protocol 0**
  (HOPOPT) packet is one such port-less protocol and is handled correctly:
  `match_source_nat_result_for_tuple` carries the L4 protocol **out-of-band** as
  `Option<u8>`, so the synthetic "L4 tuple unknown" caller (the address-only
  `match_source_nat` wrapper) is `None` while a real HOPOPT packet is `Some(0)`
  and is distinct from it (#5687). Before that fix the value 0 doubled as the
  tuple-unknown sentinel, so a real protocol-0 flow took the synthetic
  round-robin path and minted no reverse-identity token — its reverse
  translation could not be matched. The in-map / HA-sync reverse tuple key still
  stores the real protocol as a `u8` (0 for HOPOPT), so the layout is unchanged;
  only the in-code "is this unknown?" test moved out-of-band. `port
  no-translation` preserves the
  id just as it preserves a TCP/UDP source port. By default, pool address
  selection is round-robin within the packet address family. For an
  address-only flow (`port no-translation` / a port-less protocol) the
  round-robin selection **probes the whole pool from its round-robin start**
  (`reserve_address_only_roundrobin`), mirroring the port-translating
  `allocate_translation` loop: if the chosen address's reverse identity
  `(protocol, pool_addr, preserved id, remote)` is already owned by a different
  flow for this remote, it rotates to the next pool address and mints the token
  on the FIRST free sibling, failing as exhaustion **only** when every pool
  address collides. Before #6226 the address-only branch single-probed one
  round-robin address and falsely returned exhaustion (→ drop) the moment that
  one address collided, even though a sibling address was free for the same
  remote — the shared round-robin counter is oblivious to per-remote occupancy,
  so any unrelated flow advancing it could land a later flow on an owned
  address. An `address-persistent` pool keeps its single-probe contract (the
  sticky address is intentional, not round-robin); the deterministic-CGNAT
  (#5341) and address-only persistent-NAT (#6041) branches likewise single-probe
  their chosen address. With global source
  NAT `address-persistent`, the userspace dataplane hashes a domain-tag seed,
  address family, and canonical source IP bytes with a seeded non-cryptographic
  FxHash (`rustc_hash`) to choose a stable pool index (userspace-v2; #2349
  replaced the prior SHA-256 selector — this is load distribution, not a
  security primitive). See `docs/userspace-dataplane-gaps.md` (Source NAT pool
  mode) for the authoritative algorithm/contract. This is sticky within the
  current pool size and order; changing either can remap existing source IPs to
  different pool addresses.
  This is intentionally documented as a userspace-only algorithm, not
  mixed-backend new-flow parity: legacy eBPF uses C-word IPv4
  modulo and IPv6 lane-XOR selection (DPDK retired #1525). Active synced sessions carry the chosen
  translated tuple, but new allocations after backend rollback may choose a
  different pool address. Pool-mode rules with missing pools, empty pools,
  invalid port ranges, malformed addresses, no address for the packet family,
  or exhausted translated tuples fail-closed at the current
  `poll_descriptor.rs` source-NAT call sites before session creation or
  forwarding, and record recent-exception reasons such as
  `source_nat_pool_missing`, `source_nat_pool_empty`,
  `source_nat_pool_invalid_port_range`, and `source_nat_pool_exhausted`.
  Per-pool `persistent-nat` lease reuse is helper-local userspace runtime
  state keyed by source tuple `(protocol, source IP, source port)` to
  translated tuple. Compatible in-process snapshot refreshes preserve it;
  helper restart does not. #1449 closes HA behavior as an explicit userspace
  capability gate: HA configs using persistent source-NAT pools are not
  admitted because persistent leases are not synchronized.
- **Rule-set precedence — most-specific-scope-wins (#4161).** When several
  source-NAT rule-sets overlap on a flow, selection follows Junos: the rule-set
  whose match CONTEXT is most specific wins — **interface > zone >
  routing-instance > unscoped** — and only THEN does within-rule-set rule order
  apply. This is NOT config-order first-match. The Rust matcher
  (`match_source_nat_result_for_tuple`, `nat/source.rs`) is a first-match loop
  over the published slice; precedence is achieved entirely on the Go side by
  **stable-sorting** the emitted `SourceNATRuleSnapshot` slice by context tier
  in `buildSourceNATSnapshotsWithFeeds` (`pkg/dataplane/userspace/nat.go`)
  before publishing, so "first match" == "most-specific match". The tier is a
  pure function of the six scope fields already carried since #3096
  (From/To Zone/Interface/RoutingInstance); a rule-set carrying both a `from`
  and a `to` context of different kinds is ranked by the MORE-specific of the
  two (`tier = MIN(from-tier, to-tier)`, the vSRX default). Same-tier ties keep
  config order (stable sort), and each rule-set's rules stay contiguous, so
  rule-sets never interleave. This aligns SNAT with the DNAT/static
  most-specific-wins DIRECTION, though those two tables currently rank only
  zone-scoped-vs-zone-wildcard (a narrower axis that does not yet rank interface
  above zone) — extending the full hierarchy to them is a tracked follow-up.
- **Checksum update:** Incremental RFC 1624 checksum adjustment for
  IP header + TCP/UDP pseudo-header. Avoids full recomputation.

#### Policy Evaluation (`policy.rs`)

Ordered rule matching against zone pairs, address books, and applications:

```
for rule in rules:
    if rule.inactive:
        continue
    if rule.from_zone matches ingress_zone
       AND rule.to_zone matches egress_zone
       AND rule.source matches src_ip
       AND rule.destination matches dst_ip
       AND rule.application matches (proto, src_port, dst_port):
        return rule.action  // Permit or Deny
return default_deny
```

Address book entries support IPv4/IPv6 prefixes. Application matching
supports protocol + port ranges. `rule.inactive` is the policy-scheduler result
published by the Go daemon; inactive scheduled rules are skipped before any
match side effects or counters.

**Zone-pair resolution — the egress half (#6713).** `ingress_zone` and
`egress_zone` above are u16 ids resolved by
`forwarding::zone_pair_ids_for_flow_with_override`. The ingress half reads
`ForwardingState::ifindex_to_zone_id`; the egress half calls
`ForwardingState::egress_zone_id`, which prefers the denormalized
`EgressInterface.zone_id` (one map lookup + a field load on the hot path,
**including when that field is 0** — see the short-circuit below) and falls back
to `ForwardingState::ifindex_unambiguous_zone_id` when the interface has **no
`egress` row at all**.

That fallback is load-bearing, not defensive. `forwarding_build::populate_egress`
builds an `EgressInterface` only for an interface whose link-layer address it can
resolve — the row carries `src_mac` + `bind_ifindex`, i.e. an assertion that an
Ethernet frame can be built for it and handed to an AF_XDP bind target. An IPsec
secure tunnel (`st0`, an xfrmi) is `ARPHRD_NONE` and fails that gate
unconditionally: `hardware_addr` is empty, `mac_by_ifindex[parent]` is absent
(the parent is itself a MAC-less xfrmi), and `iface.tunnel` means a Junos
`tunnel { source destination }` stanza that `st0` does not have. Reading the
to-zone from `egress` alone therefore yielded id **0** for a correctly-zoned
tunnel — and 0 is the reserved "unknown zone" sentinel that
`evaluate_policy_result_l3_aware` refuses to match ANY exact, wildcard or
`junos-global` rule against. Every LAN→tunnel packet was adjudicated as
`(lan, 0)`, no operator-authored permit could apply, and the drop was attributed
to the implicit default policy — pointing every diagnostic at the wrong place.

Scope of the fallback:

- **An ifindex is not a unit identity, so the fallback refuses to guess (#6722).**
  `pkg/dataplane/userspace/interfaces.go`'s `snapshotLinuxName` collapses a
  non-VLAN unit 0 onto its base netdev, so `st0` and `st0.0` are ONE ifindex, as
  are `ge-0/0/1` and `ge-0/0/1.0`. And `buildInterfaceZoneMap`
  (`pkg/dataplane/userspace/zones.go`) writes `out[base]` for a unit-suffixed
  zone reference, so zoning `st0.1` zones `st0` as well. `ifindex_to_zone_id` is
  therefore a per-NETDEV map: the last zoned row on that ifindex, plus the zone
  `populate_interfaces` propagates from a zoned child unit onto
  `parent_ifindex`.

  Reading it as the egress answer hands an interface a nonzero zone it was never
  configured with — and a nonzero to-zone is exactly what makes an operator's
  permit MATCH, so that direction is fail-OPEN. Three producible shapes do it:

  1. Zone only `st0.1`; the Go builder still stamps the `st0` BASE row with
     `vpnb`, and `st0.0` — which the operator deliberately left in NO zone —
     shares the base's ifindex.
  2. Two units in DIFFERENT zones on one `st0` with unit 0 unzoned. The
     `out[base]` write is first-write-wins over SORTED zone names, so unit 0's
     ifindex carries the alphabetically-first sibling's zone.
  3. StableZoneID quarantine (`zones_quarantine.go`), which blanks `Zone` on the
     interfaces of a colliding zone AFTER `buildInterfaceSnapshots` ran,
     precisely so they fail CLOSED. The base arrives unzoned beside a surviving
     zoned child, the Rust child→parent propagation re-zones the parent ifindex,
     and reading it would hand the quarantine's deliberate default-deny back the
     survivor's zone.

  So the fallback reads `ifindex_unambiguous_zone_id`, built in
  `populate_interfaces` over ALL snapshot rows — zoned and unzoned alike. An
  ifindex appears there only when every CONTRIBUTING row sharing it named the
  SAME nonzero zone — a RETH member's row is a projection rather than an
  independent observer and is exempt from voting (#6722 B2, below), so
  unanimity is over the observers rather than over the raw row set;
  disagreement (including "one row zoned, one row not") and unanimous "no
  zone" are both absent, and `egress_zone_id` then resolves the **0 sentinel** —
  the pre-#6713 answer, against which no exact, wildcard or `junos-global` rule
  matches, so the default policy decides.

  This deliberately makes the two DIRECTIONS disagree for an ambiguous ifindex:
  ingress still attributes an arriving packet to `ifindex_to_zone_id`
  (#921/#3618, unchanged), while egress answers 0. The asymmetry is justified by
  DIRECTION, not by the ingress surface being unreachable — that is only true in
  shape 3, where every row is unzoned and `interfaces.go`'s
  `if iface.Zone == "" { continue }` gives the ifindex no AF_XDP bind target at
  all. In shapes 1 and 2 the base row is zoned, so the ifindex *is* a bind
  target and ingress really does answer `vpnb` for arriving traffic. What makes
  the two halves different is that ingress answering wide is pre-existing
  behaviour this change does not touch, while egress answering wide is a NEW
  fail-open on the exact interface class #6713 routed through the fallback:
  a to-zone is what makes a permit match. Whether the ingress half should be
  narrowed the same way is a separate #921/#3618 question, not settled here.
  Where the ifindex is UNambiguous — #6713's own shape, `bind-interface st0`
  with its unit in the same zone — both halves still answer the same zone, so
  #6713 is untouched.

  Junos zones logical UNITS, so the remaining gap runs the other way: `st0.0`
  and `st0.1` cannot be given DIFFERENT zones and both forward. Closing that
  needs per-unit identity end to end — the snapshot's unit-0 ifindex collapse,
  both halves of the zone resolver, and the AF_XDP bind keying — and is tracked
  separately rather than papered over at this one read. Until then such a pair
  fails closed rather than guessing.

  The Rust child→parent zone propagation in `populate_interfaces` is
  **reachable** for a Go-produced snapshot: shape 3 above is the counterexample.
  `pkg/dataplane/userspace/zone_propagation_6722_test.go` measures all of it —
  the `out[base]` write, the unit-0 ifindex collapse, and (through the full
  `buildSnapshot`, on the lenient load path the strict commit gate rejects) the
  post-quarantine unzoned base beside a surviving zoned child — so the
  userspace-dp fixtures modelling these shapes cannot drift to a snapshot the
  builder cannot emit.
- **The egress row's `zone_id` comes from the ledger too (#6722 B1).**
  `egress_zone_id` reads `state.egress` BEFORE the fallback, and
  `populate_egress` writes that map **last-write-wins per ifindex**. While the
  row's own zone was the source, a zoned row emitted last re-armed an ifindex
  the ledger held ambiguous and the gate was bypassed entirely — the to-zone
  never consulted the ledger at all.

  That is not confined to MAC-less interfaces. An interface-level WireGuard
  tunnel maps EVERY unit onto the base device (`TunnelNameMap`,
  `pkg/config/types.go`, whose interface-level branch explicitly admits
  WireGuard despite its empty GRE-style `source`), so `wg0`, `wg0.0` and
  `wg0.1` are one netdev and one ifindex; they carry `tunnel = true`, so
  `populate_egress`'s `src_mac` gate admits them via
  `iface.tunnel.then_some([0; 6])` and they DO get egress rows. Zone only
  `wg0.1` and transit routed out the deliberately-unzoned `wg0.0` matched
  `from-zone lan to-zone vpnb permit`.

  `populate_egress` therefore takes `zone_id` from
  `ifindex_unambiguous_zone_id`, so both arms of the resolver derive from one
  source and cannot disagree. Where the rows agree the value is identical to the
  row's own zone, so an ordinary single-unit interface is unaffected.

- **A RETH member's row is a PROJECTION, not an observer (#6722 B2).**
  A ledger is only sound if every row voting on an ifindex is an INDEPENDENT
  observer of it. There is a third way several rows land on one ifindex, and it
  is the only one that reaches a shipped topology: `ResolveReth`
  (`pkg/config/types.go`) resolves a RETH to its PHYSICAL MEMBER, and
  `snapshotLinuxName` applies it to the reth base row AND its units. So
  `ge-0/0/1`, `reth1` and `reth1.0` are one netdev, and a member's own units
  alias the matching reth unit the same way — a VLAN unit resolves to
  `LinuxIfName(ResolveReth(base)).<vlan>`, putting `ge-0/0/1.100` on
  `reth1.100`.

  Junos configs conventionally zone the RETH rather than the member, so
  `buildInterfaceZoneMap` usually leaves the member's rows unzoned and
  `buildInterfaceSnapshots` emits them unfiltered. This is convention, not a
  code property — `buildInterfaceZoneMap` enforces no such rule and a config
  zoning the member yields a zoned member row (measured:
  `zoneByInterface[ge-0/0/1] = "z214"`). The gate does not rely on it; its
  `zone.is_empty()` half handles the exception.
  Measured through the full `buildSnapshot` on `docs/ha-cluster-userspace.conf`
  (node 0 — the topology `test/incus/loss-userspace-cluster.env` points every HA
  smoke test at):

  ```
  ifindex 24: [ge-0/0/1="" reth1="lan" reth1.0="lan"]   <-- DISAGREE
  ifindex 25: [ge-0/0/2="" reth0="wan"]                 <-- DISAGREE
  DefaultPolicy="deny"
  ```

  Counting the member's "no zone" as dissent held those ifindexes ambiguous,
  collapsed the egress zone to the 0 sentinel and — under `deny-all` — blackholed
  every WAN→LAN, sfmix→LAN and tunnel→LAN transit flow on a bondless-RETH
  cluster. LAN→WAN survived because its egress ifindex has a single row, which is
  why an iperf3 smoke in the usual direction came back green. The INGRESS half
  was unaffected throughout (`ifindex_to_zone_id[24]` still carried `lan`); that
  asymmetry is the diagnostic tell.

  So the Go builder marks every row of a RETH physical member that lands on the
  RETH's netdev (base AND units) with `reth_projection`, and
  `populate_interfaces` exempts a row that carries it **and has no zone of its
  own** from voting. The `zone.is_empty()` half is
  load-bearing: a member the operator EXPLICITLY zoned into a different zone than
  its RETH is a real statement about a real conflict, not an artefact of one
  device described by several rows, and it must keep failing closed
  (`explicitly_zoned_reth_member_still_makes_the_ifindex_ambiguous_6722`). The
  exemption reaches nothing else — `st0.0` and `wg0.0` are genuine logical units
  and still vote (`reth_exemption_does_not_leak_to_iface_tunnel_units_6722`), and
  `fab0` is not a fourth mechanism at all: the fabric IPVLAN is its own netdev
  with its own ifindex (`snapshotLinuxName` never calls `ResolveFab`).
- **`reth_projection` is decided in Go, not re-derived in the helper.** The
  wire carries the ANSWER; `populate_interfaces` reads it and computes nothing.
  That split is the fix, not an implementation detail. The field's predecessor
  carried the raw `redundant-parent` string, and `redundant-parent` is
  unvalidated operator input: nothing requires the interface it names to exist,
  to be a `reth*`, to declare a redundancy-group, or to differ from the
  interface naming it, and `schema_interfaces.go` accepts `gigether-options`
  under any interface name. Every re-derivation from that string was therefore a
  predicate the operator could satisfy by choosing names, and three successive
  spellings were holed in turn by configs strict `CompileConfig` accepts — the
  last by `set interfaces st0 gigether-options redundant-parent st0`, where
  `st0.0` matched its own co-resident BASE row (base and unit-0 are one netdev
  by the non-VLAN unit-0 collapse), exempted itself, and flipped
  `egress_zone_id` from the fail-closed `0` to `vpnb` — measured end to end
  through the real builders as `ledger[42]=Some(32521)`, `egress_zone_id=32521`,
  `action=Permit`.

  `rethProjectionNetdevs` (`pkg/dataplane/userspace/interfaces.go`) answers it
  where `ResolveReth` and the whole interface table are in hand. A row is a
  projection when its `redundant-parent` names a **declared**
  redundant-ethernet interface (present, `redundancy-group N`), that interface
  is a **different** one, and the row **lands on a netdev the parent's own rows
  occupy** — the last computed by evaluating `snapshotLinuxName` on the parent,
  the same function that creates the aliasing. The Go-side cells are pinned per
  clause in `pkg/dataplane/userspace/reth_member_projection_6722_test.go`
  (`TestSelfNamedRedundantParentIsNotAProjection_6722`,
  `TestUndeclaredParentIsNotAProjection_6722`,
  `TestMemberUnitOffTheRethsNetdevsIsNotAProjection_6722`).

  A `reth*` with no declared `redundancy-group` is accepted by the compiler and
  is deliberately NOT treated as a RETH here — the same test the adjacent
  `rethRG` lookup already applies. Its members keep voting, so such an ifindex
  stays ambiguous and its egress zone stays at the `0` sentinel; declaring the
  redundancy group is the fix. Every RETH config in this repository declares
  one.

  The field is additive in both directions — `omitempty` on the Go side,
  `#[serde(default)]` on the Rust side, and no `deny_unknown_fields` anywhere in
  `userspace-dp/src/protocol` — and the DEGRADED direction is the fail-CLOSED
  one under the reference cluster's `default-policy deny-all`: an old helper
  ignores the key, an old Go binary omits it, and in both cases the member votes
  and the ifindex stays ambiguous. Read the next bullet before calling that
  "safe" without qualification — under `permit-all` the same degraded direction
  is fail-OPEN, and the two bullets contradicted each other until #6722's
  re-gate.

- **Both directions of the 0 sentinel, stated.** The sections above argue the
  fail-CLOSED consequence because that is what the reference cluster runs
  (`default-policy deny-all`). Under `default-policy permit-all` the same
  resolution is fail-OPEN: zone id 0 matches no rule in ANY tier — exact pair,
  from-any, to-any, both-any or `junos-global` — so a DENY the operator wrote for
  that zone pair is skipped along with everything else and the permissive default
  decides. Refusing to guess a zone is therefore not universally "the safe
  answer"; it is safe exactly to the extent the default policy is. This is
  consistent with the pre-existing #3110 decision to treat zone 0 as
  unmatchable rather than as a wildcard, and it is why #6722 B2 is a blocker
  rather than a cosmetic correctness fix: on a deny-all cluster the ambiguity
  cost total LAN reachability, and on a permit-all one it would cost the
  operator's deny rules instead.

  **Provenance, stated so a bisect is not misled.** This ambiguity was already
  latent in the index-keyed `egress` map before #6713/#6722: on `origin/master`
  `egress_zone_id` was an `egress`-only read and `populate_egress` already
  sourced the row's own zone last-write-wins, so the WireGuard shape above
  already adjudicated `vpnb` there. #6713 did not create the defect — it added
  the fallback and routed more consumers through the same incomplete resolver,
  widening the blast radius without enforcing the invariant it stated. What the
  ledger adds is the enforcement: the gate now covers BOTH arms, so the
  pre-existing case is closed rather than merely narrowed.

- A row that exists carrying `zone_id == 0` still stays 0. That short-circuit is
  **load-bearing, not defensive**: a zoned trunk with a declared but unzoned
  unit 0 (`ge-0/0/9` zoned `lan`, `ge-0/0/9.0` in no zone, both MAC-ful, both
  ifindex 90) must resolve 0, and
  `unzoned_interface_with_egress_row_stays_zone_zero_6713` reds on its removal.

  For an ifindex that HAS an egress row the resolved to-zone is **not**
  universally bit-identical to the pre-#6713 read, and an earlier revision of
  this section wrongly claimed it was. It is bit-identical for every ifindex
  whose rows AGREE — which is every ordinary single-unit interface, and so the
  overwhelming majority — and it is deliberately DIFFERENT where they disagree.
  `[Z, 0, Z]` is the direct counterexample: the pre-#6713 read returned the last
  row's `Z`, the ledger returns `0`. That change IS the point of #6722, not an
  incidental side effect, and it is the one case where an egress-row interface's
  adjudicated to-zone moves.

  Before #6722 B1 that outcome held only by EMISSION-ORDER luck — the unzoned
  unit-0 row happened to be written last, so 0 won the last-write. Reverse the
  order, as the WireGuard shape does, and the zone won instead. Sourcing the
  egress row's zone from the ledger makes the short-circuit correct **by
  construction**: an ifindex whose rows disagree carries 0 regardless of which
  row the builder emits last.
- `egress_zone_id` is the single egress-zone resolver: policy adjudication, the
  #3651 per-zone traffic counter, the filter-log `egress_zone_id` field (both
  the flow-cache-hit path via `filter_log_egress_zone_id` and
  `forward_request`'s own independent call), and the local-origin tunnel TX
  path's `SyncedSessionEntry` zones all route through it, so the adjudicated
  zone and the logged/counted zone do not disagree.

  That holds **by enumeration of the callers, not by construction** — nothing
  prevents a new site from reading `state.egress` directly and silently
  reintroducing the #6713 split. Four sites are pinned by tests
  (`zoned_macless_unit_still_reaches_policy_6713`,
  `filter_log_egress_zone_id_reports_a_macless_tunnels_zone_6713`,
  `cached_output_filter_log_reports_the_adjudicated_zone_6722` — which drives
  the production `emit_cached_output_filter_log_tail` rather than the helper —
  and `build_live_forward_request_logs_a_macless_egress_zone_6713`). The
  zone-accounting readers (`disposition.rs`, `flow_cache_hit.rs`, the slow path)
  are **not**, so a direct `state.egress` read added there would not be caught
  by this suite. Route new consumers through the resolver.
- The MAC-less interface is still ABSENT from `state.egress`, so nothing on the
  TX path changes: `session_glue::populate_egress_resolution` still leaves
  `src_mac = None` and `tx_ifindex = egress_ifindex` for it, and the packet still
  reaches the kernel through the slow-path reinject rather than an AF_XDP TX with
  an all-zero source MAC on a link-layer-less device.

**Downstream consumers of the corrected to-zone.** Resolving a real to-zone
where the code previously saw 0 changes more than the policy verdict. All are
correct-direction — the zone the operator configured is finally the zone the
dataplane uses — but they are behavior changes on a LAN→tunnel flow and are
listed here so a bisect does not have to rediscover them. Every entry is scoped
to an **unambiguous** ifindex: an ambiguous one resolves 0, so none of these
fire for it. Note that "resolves 0" is only bit-identical to pre-#6713 for an
ambiguous ifindex with NO egress row; one that HAS an egress row previously
resolved whichever zone `populate_egress` wrote last, so for it this is a
deliberate change (see the `[Z, 0, Z]` counterexample above):

- **Source-NAT rule-set scoping** and the `MissingNeighborSeed` metadata now see
  the tunnel's zone; a rule-set scoped `to zone <vpn>` fires where it did not.
- **NPTv6 outbound translation** (`poll_descriptor::translate_outbound`, plus the
  fragment probe in `frag_assoc`) is egress-zone-scoped by #5176, so an NPTv6
  rule-set scoped to the tunnel's zone now translates LAN→tunnel traffic. This is
  a *translation* change, not only a policy change.
- **Fabric zone-encoded redirect.** The reverse companion of a LAN→tunnel
  session carries the forward session's egress zone as its `ingress_zone`, so
  when locally HA-inactive it emits a zone-stamped synthetic fabric source MAC
  where it previously emitted the real fabric MAC. The receiving side gates the
  decode on `zone_encoded_fabric_stamp_valid`, which requires `zone_to_rgs[zone]`
  to be non-empty — and `populate_zone_to_rgs` reads `state.egress`, which a
  MAC-less tunnel has no row in. For a tunnel-only zone the stamp is therefore
  rejected and the frame degrades to an ordinary unstamped fabric-ingress
  packet: wire-visible on the HA fabric, but graceful, with no drop.
- **Per-zone half-open window.** The #3527 SYN-flood `timeout` override is keyed
  on the reverse companion's `ingress_zone`, so the tunnel zone's override now
  applies where the global default used to.

**Upgrade direction.** The change is bidirectional, not permit-only. Under
`default-policy permit-all` plus an explicit `from-zone lan to-zone <vpn> ...
then deny`, the pre-#6713 build adjudicated `(lan, 0)` → default permit → traffic
flowed; it now adjudicates `(lan, vpn)` → the operator's deny matches → traffic
STOPS on upgrade. That is the configured verdict finally being honored, but it
is a live-traffic change in the deny direction.

**Malformed-address fail-closed (#3367 legacy, #3711 v3 + books).** Every
address parse path in the snapshot builder REPORTS an unparseable token and
fails the WHOLE snapshot closed rather than silently dropping it. Silent-drop is
a security fail-OPEN: a v3-shaped rule side and a book entry both use the
`from_v3_literals` factory (empty → `MatchNone`), so an all-dropped side
collapses to `MatchNone` — a `deny <malformed>` rule then matches nothing and
evaluation falls through to a later permit / default-permit. The legacy
`source_addresses` / `destination_addresses` field is reported by
`parse_legacy_address_set` → `SnapshotIntegrityError::UnrepresentableLegacyAddress`
(#3367; note the legacy empty→`MatchAny` convention makes an all-malformed
legacy list widen a deny to match-all — the inverse fail-open, same reject). The
v3 `source_literals` / `destination_literals` field is reported by
`parse_v3_literal_set` → `UnrepresentableV3Address` (#3711). The address-book
`prefixes_v4` / `prefixes_v6` arrays are parsed by `parse_book_prefix_into` →
`UnrepresentableAddressBookPrefix` (#3711), which additionally ENFORCES the
declared family (M02): a wrong-family token — e.g. an IPv6 CIDR placed in
`prefixes_v4` by a corrupt / mixed-version producer — is rejected instead of
being silently routed into the opposite family's set. The `__unsupported_address__`
sentinel preflight (`UnrepresentableAddress`, #3261) is checked FIRST, so the
more-specific "undefined book / non-literal value" diagnostic wins over the
generic malformed-literal error for the token the Go gate emits. A normal Go
snapshot only ever emits parseable, family-separated literals / `any` / family
wildcards, so these rejects guard against a corrupt / hand-built / mixed-version
HA peer-sync snapshot; the preflight keeps the previous good forwarding state.

**Legacy `any` mixed with literals stays match-all (#3947).** `parse_legacy_address_set`
now treats a bare `any` token exactly like `parse_v3_literal_set` — it sets
BOTH per-family match-all flags (`any_v4`/`any_v6` → `MatchAny`), regardless of
any literals or family-scoped wildcards present in the same list. The pre-fix
no-op arm (`"any" | "" => {}`) leaned on the legacy empty→`MatchAny` convention,
which only yields match-all when the list is otherwise EMPTY; a list MIXING
`any` with a literal (`[ any 10.0.0.0/8 ]`) DROPPED the `any` and NARROWED the
match set to just the literal. For a DENY term that narrowing is a fail-OPEN: a
deny meant to match every source (`any`) matched only the listed literal, so
traffic from other sources fell through to a later permit / default-permit. The
empty (`""`) token remains a no-op — distinct from `any` — so an otherwise-empty
list still collapses to `MatchAny` via `from_prefixes`, but a mixed
`[ "" 10.0.0.0/8 ]` keeps the literal scoping. This only bites the drift /
hand-built / mixed-version-decode legacy path; a normal Go v3 snapshot never
uses the legacy field.

**Duplicate rule-identity fail-closed (#3713).** `parse_policy_state_with_counters`
preflights rule-identity uniqueness BEFORE it allocates any per-rule hit counter
or builds a `PolicyRule` entry — the FIRST validation in the function, so no
transient counter is get-or-inserted into the shared `PolicyCounterStore` for a
snapshot that is then rejected. Two failure modes are rejected:
`SnapshotIntegrityError::DuplicateRuleId` when two rules resolve to the same
stable `rule_id` (`stable_policy_rule_id` returns an explicit wire `rule_id`
verbatim, else the synthesized `from->to/name` key — an identical explicit id or
a duplicate policy name in one zone pair collides), and
`SnapshotIntegrityError::DuplicatePolicyId` when two rules carry the same
positional `policy_id`. Both alias the runtime identity: `rule_id` is the
get-or-insert key for `PolicyCounterStore::rule_hit_counter`, so a duplicate
would make two rules SHARE one `Arc<PolicyRuleCounter>` and `counter_snapshots()`
would emit two rows with the same id and the same collapsed totals (hit-count
mis-attribution); `policy_id` is the RT_FLOW / `SESSION_CLOSE` / display join key
AND the last-writer-wins value in `rule_id_to_policy_id`, so a duplicate lets an
existing session re-resolve (#3395 live-row refresh) to the WRONG policy. The Go
builder (`walkPolicyRuleSlots`) assigns each policy a distinct positional
`policy_id` (`policy_set_id * MAX_RULES_PER_POLICY + rule_index`) and a distinct
stable `rule_id` by construction, so a clean commit never trips these; they are
the helper-boundary backstop for a corrupt / hand-built / mixed-version HA
peer-sync snapshot. The `policy_id` check (M01) excludes two values: the
reserved implicit-default sentinel (`DEFAULT_POLICY_SENTINEL_ID`, `u32::MAX`),
never carried by a configured rule; and `0`, the `omitempty` wire zero-value
that is simultaneously the valid FIRST-policy id AND the "unspecified" value a
pre-`policy_id` (pre-#3056/#3057) producer or an older HA peer leaves on EVERY
rule — rejecting a duplicate `0` would fail-close a legitimate older-peer /
hand-built (all-zero) snapshot, an availability regression during a rolling
upgrade rather than the aliasing corruption this guards. A genuine collision of
two distinct rules on a real assigned (non-zero) positional `policy_id` is still
caught. Rejecting the whole snapshot mirrors `DuplicateAddressBookId` and keeps
the previous good forwarding state.

**Wildcard zone tiers (#3090).** A policy whose `from-zone` or `to-zone` is the
Junos wildcard `any` is indexed into one of three dedicated lists alongside the
exact `zone_pair_index`: **from-any** (key = concrete to-zone id), **to-any**
(key = concrete from-zone id), and **both-any** (matches every pair).
`evaluate_policy_result_with_icmp` consults them in Junos most-specific-first
precedence:

```
exact (from,to)  →  single-wildcard (from-any ∪ to-any, merged in config order)
                 →  both-any  →  junos-global  →  default policy
```

Each tier is an O(1) FxHashMap probe (or a small Vec scan only when wildcard
rules exist), so a config with no wildcard policy pays only two empty-slice
probes per cold-path evaluation — no N×N materialization of concrete pairs. A
`from-zone any to-zone junos-host` rule is enforced on the host-bound path too
(`evaluate_junos_host_policy`); `to-zone any` / `from-zone any to-zone any` are
deliberately not applied to host-bound traffic to preserve the management
lifeline guarantee. This lifted the #3018 interim commit reject.

**Cold-path histogram slot coverage for wildcard/global policies (#3783).**
The first-packet latency histogram (#1635, sparse slot map since #3075) is
keyed at record time on the CONCRETE `(from_zone_id, to_zone_id)` a packet
traverses (`poll_descriptor::lookup_slot`), and its slot set comes from
`PolicyState::configured_zone_pairs()`. That function originally enumerated
ONLY the exact `zone_pair_index` keys, so a deployment whose only rules are
`from-zone any to-zone <z>` / `to-zone any` / `from-zone any to-zone any` or
`security policies global` produced ZERO exact pairs — the concrete pair a
packet actually took had no slot and the latency sample was silently dropped,
dark-ing the instrument for exactly the catch-all designs operators commonly
deploy. `configured_zone_pairs()` now emits two tiers: (1) the exact pairs
FIRST (they keep slot priority so a mixed config never starves a named pair),
then (2) the concrete pairs the wildcard/global scopes can match, materialized
from the snapshot's concrete-zone universe (`PolicyState::concrete_zone_ids`,
every non-zero non-reserved id in `zone_name_to_id`) constrained by each scope —
`from-zone any to-zone Z` → every `(f, Z)`; `to-zone any from-zone F` →
every `(F, t)`; both-any → the full cross-product; a `junos-global` rule → the
cross-product narrowed by its `match from-zone`/`to-zone` `GlobalZoneScope`
(#3148). The expansion is config-derived and deterministic, so both HA nodes
build the identical slot map from the identical config (the histogram counts
are per-node local telemetry scraped via status/Prometheus — not wire-synced —
but the slot LAYOUT stays symmetric). If the union exceeds the 255-slot
capacity the surplus is dropped by `ColdPathSlotMap::build` and surfaced via its
`overflow_active` flag; exact pairs are assigned first, so they win under
pressure.

**Global policy zone context (#3148, #4626 M03).** A Junos global policy may
carry optional `match { from-zone [ <z> ... ]; to-zone [ <z> ... ]; }` to scope
it to a set of zone pairs (or one wildcard side) instead of every zone pair. The
scope is a zone **SET** on each side: a packet matches the global iff its
from-zone ∈ the from-set AND its to-zone ∈ the to-set. Such a rule keeps the
`junos-global` sentinel on its structural zones (so it stays classified in the
`global_indices` tier and the global config order is preserved) and carries its
context out-of-band on ADDITIVE wire fields. The singular `match_from_zone` /
`match_to_zone` keep the FIRST zone (`config.ScopeSingular`); the plural
`match_from_zones` / `match_to_zones` are AUTHORITATIVE and carry the full set.

**The singular field is a display/degradation shape, NOT a rolling-upgrade
compatibility guarantee (#5488).** #4626 added the plural fields as purely
ADDITIVE JSON while leaving `CONFIG_SNAPSHOT_PROTOCOL_VERSION` at 3 — the same
value a pre-#4626 helper advertises and accepts. That made the version handshake
say "we agree" while the two sides disagreed about what the message meant: an
old helper ignores the plural fields it does not know, reads only the singular
one, and NARROWS a global `deny` scoped `[dmz trust] -> untrust` to
`dmz -> untrust`, so trust-sourced traffic the operator denied falls through to
lower-precedence rules — a rolling-upgrade fail-OPEN. The version is now **4**
and the two constants are pinned in lockstep (see *Config-snapshot protocol
version* below), so a multi-zone scope can never reach a reader that would
narrow it.

`parse_policy_state` prefers the plural (falling back to `[singular]`) and
resolves it at snapshot-build time into a `GlobalZoneScope` — `Any` for no
constraint, `Zones(SmallVec<[u16; 2]>)` for a set of defined zone ids
(sorted+deduped), and an unresolvable element fails the WHOLE snapshot closed
(`UnresolvableZoneReference`, #3402). An OMITTED leaf and any `"any"` element
both map to `Any` (all zones, the Junos implicit default) —
`build_global_zone_scope` short-circuits `"any"` so it can never route to a
matches-nothing scope, keeping the dataplane in agreement with the Go commit
gate (which exempts `any` and rejects a list that MIXES `any` with concrete
zones). A single-zone scope is a 1-element `Zones` set, bit-identical to the
pre-#4626 `Zone(id)` model. The reserved `junos-host` zone is direction-split as
a global match context (#3639 / #3611 Piece B): `match to-zone junos-host`
(host-INBOUND) commits and IS enforced — `evaluate_junos_host_policy_l3_aware`
consults the `global_indices` tier filtered by `global_to_zone.is_host_scope()`
(the to-set is exactly `[JUNOS_HOST_ZONE_ID]`; a to-zone list that mixes
junos-host with any other zone is rejected at commit), after the exact `from-zone
<ingress> to-zone junos-host` pair and the `from-zone any to-zone junos-host`
wildcard (a scoped global stays least-specific). `match from-zone junos-host`
(host-ORIGINATED) stays hard-rejected at commit — locally generated traffic
egresses via the kernel TX path, never the AF_XDP RX gate, so it could only ever
silently never-match (#3611 Piece A, documented not built). A multi-zone scoped
global that names a zone-local address book resolves against the GLOBAL book
(zone-local resolution is defined only for a single concrete zone — a documented
parity limitation).
The scope is checked as an extra predicate
inside the `junos-global` tier loop, **in the same tier position** shown above:
a zone-scoped global policy is NOT promoted ahead of the #3090 wildcard tiers.
Precedence example — a `from-zone any to-zone untrust` wildcard (zone-pair
tier 1) wins a `trust->untrust` flow over a conflicting `global match
from-zone trust to-zone untrust` (tier 4), because the global list is always
consulted after the zone-pair lookups (matching Junos, where the global policy
list is evaluated after the from-zone/to-zone policy set). A global policy with
no zone context keeps the historical all-zones behaviour. The Go commit gate
(`validatePolicyZoneReferencesStrict`) rejects an undefined global match zone
(downgraded to a warning on the tolerant load path); the dataplane independently
fails closed (`Unresolved` matches nothing).

This scope tier is pinned as a **cross-language SSOT regression matrix** (#4365):
the Go simulator half (which backs `show security match-policies`) is
`TestSharedMatcherGlobalScopeRegressionMatrix`
(`pkg/policymatch/global_scope_regression_4365_test.go`) and the Rust dataplane
half is `global_policy_zone_scope_tier_ordering`
(`userspace-dp/src/policy_tests.rs`, #4497 F2). The two assert the same matrix
case-for-case — both-sides-match fires the scoped global, a mismatched side
falls through to the default, empty/explicit-`any` applies to every pair, and an
exact zone-pair (Tier 1) or a both-any wildcard (Tier 3) OUTRANKS a matching
global (Tier 4) — so the operator's test output can never permit/deny
differently than the wire. One deliberate divergence: a typo'd (undefined) scope
fails closed to the default in the Go simulator (which runs on
already-committed config) but fails the whole snapshot closed at build in Rust
(#3402); a typo can never commit, so neither path ever serves it.

**Unknown-zone guard (#3110).** Zone id `0` is the reserved "unknown / no
zone" sentinel — assigned to interfaces not bound to any security zone. (The
former #2391 over-cap collapse-to-0 path is retired: #3075 made zone ids a
stable u16 name-hash and an interface naming an absent zone now fails the
snapshot closed via `InterfaceUnknownZone` rather than collapsing to 0.)
`evaluate_policy_result_with_len`
evaluates zone-pair rules AND `junos-global` rules only when
`from_id != 0 && to_id != 0`. A flow whose ingress OR egress zone is unknown
does not belong to any *defined* zone pair, so it is ineligible for both
zone-scoped and global policies and falls straight through to the default
action (deny, per #3065). This prevents a configured permit-global from leaking
transit on an unzoned ingress/egress interface. The `junos-global` sentinel
zone-id (`u16::MAX`) is a *defined* global zone, distinct from `0` (unknown),
and is unaffected by the guard — global policies still apply to every defined
zone pair. The #3090 wildcard-zone tiers (from-any / to-any / both-any) live
inside the same `from_id != 0 && to_id != 0` guard, so an unzoned flow falls
through to the default action exactly like a global policy.

#### Static NAT zone scoping (`nat/static_nat.rs`)

A static 1:1 rule-set may carry a `from zone <name>` scope. The dataplane
enforces it on the inbound (DNAT) direction only: `match_dnat` skips an entry
whose `from_zone` does not exactly match the ingress zone name. The outbound
(SNAT) direction is intentionally not zone-filtered — the internal-IP match is
sufficient since the host originates the traffic regardless of ingress zone.
Because a typo'd or undefined zone produces a rule that silently matches no
inbound traffic, the Go compiler validates static-NAT `from-zone` references
against the defined zones at commit and warns on an undefined zone (mirroring
the source-NAT zone validation). Junos static NAT has no `to` clause.

**Pre-routing scope keys on the LOGICAL VLAN unit (#5802, security).** The
inbound DNAT / static-NAT / NPTv6 pre-routing lookups run before the FIB/zone
lookup, and their `from zone` / `from interface` / `from routing-instance`
scope is matched against the INGRESS identity — the zone name, config-interface
name, and routing-instance of the unit that received the frame. That identity
MUST be the LOGICAL VLAN unit, not the physical AF_XDP bind interface. On a
trunk the parent physical netdev carries every VLAN unit's frames (see *VLAN
unit AF_XDP binding target*), and `ifindex_to_zone_id` /
`ifindex_to_config_name` / `ifindex_to_routing_instance` are keyed by the
logical unit ifindex — the physical parent maps only to its FIRST unit. The
pre-routing site resolves the logical unit via `prerouting_ingress_scope`
(`poll_descriptor/mod.rs`, using `resolve_ingress_logical_ifindex` on the
`(bind ifindex, VLAN id)` key), the SAME identity the later zone-pair policy /
input-filter / CoS path uses (#3021). Before #5802 the scope was taken from the
raw physical `meta.ingress_ifindex`, so on a trunk whose units sit in distinct
zones / interfaces / routing-instances a packet on one unit could match another
unit's scoped NAT rule (or miss its own) — applying or skipping translation
outside the configured `from` boundary, ahead of the correct logical zone
policy (a NAT scope-escape). An untagged port has no `(parent, VLAN)` mapping,
so it resolves logical == physical and the scope is byte-identical to pre-#5802.

#### Slow Path (`slowpath.rs`)

A TUN device (`xpf-usp0`) for packets that need kernel processing:

- ICMP reject responses (policy deny with reject action)
- Packets that fail forwarding resolution
- Rate-limited: 2000 pps, 16 MB/s (prevents flooding kernel)
- Async writes via io_uring (non-blocking on worker thread)
- Bounded channel (256 depth) between enqueue and writer thread
- **TUN MTU (#2408):** the kernel creates the TUN at the default 1500 MTU.
  `slow_path_worker` programs it via `SIOCSIFMTU` (`set_if_mtu`) to the
  largest configured data-interface MTU — `ConfigSnapshot::slow_path_mtu()`,
  the max of the per-interface MTUs the control plane carries in the
  snapshot, clamped to a 1500 floor. Without this a reinjected jumbo frame
  (> 1500 bytes on a jumbo-frame topology) is silently dropped on the TUN
  egress. A failed `SIOCSIFMTU` is non-fatal: it is logged and recorded in
  `last_error`, and the TUN stays usable for frames up to its current MTU.
  - **Degraded reporting (#2471):** a failed `SIOCSIFMTU` no longer hides
    behind a bare `active = true`. `apply_mtu_status` falls the live MTU back
    to the kernel-default 1500 (`live_mtu` in the status), sets `degraded =
    true`, and records the ioctl error. The reinjector's `enqueue` then
    REFUSES any frame larger than `live_mtu` (returning
    `EnqueueOutcome::MtuExceeded`, counted in `mtu_dropped_packets` and
    `dropped_packets`/`dropped_bytes`) instead of handing it to the kernel to
    be silently dropped on TUN egress. The slow path remains usable for
    <=1500 frames, so this is degraded — not unusable — capacity. All three
    fields (`degraded`, `live_mtu`, `mtu_dropped_packets`) cross the control
    socket (Rust `protocol/control.rs` SlowPathStatus → Go
    `pkg/dataplane/userspace/protocol_status.go` SlowPathStatus, tag-matched) and
    surface in `show ... slow path` output: a `Slow path DEGRADED: true` line,
    the live MTU, and the MTU-exceeded drop counter.
  - **Day-2 reconcile (#5801):** the MTU is programmed when the worker opens
    the TUN (first apply, i.e. `apply_snapshot`'s `preserved_slow_path ==
    None` branch). Later reconciles PRESERVE the running reinjector rather
    than re-opening the device, so a config MTU change committed while the
    daemon is running would leave the live TUN at its startup ceiling — the
    accepted snapshot then advertises a jumbo MTU while reinjected frames
    above the old ceiling drop persistently (`MtuExceeded`) until restart.
    The reconcile path now CONVERGES the live TUN instead of only warning:
    when `snapshot.slow_path_mtu()` differs from the preserved reinjector's
    live MTU, `apply_snapshot` calls `reconcile_preserved_slow_path_mtu`,
    which invokes `SlowPathReinjector::reconcile_mtu` to reprogram the live
    device via `SIOCSIFMTU` and update the reinjector's `mtu()`, `live_mtu`,
    and enqueue admission together. First-boot jumbo configs remain covered by
    the creation branch. The `SIOCSIFMTU` seam is injected into
    `apply_snapshot` (production passes `set_if_mtu`) so the wiring — that the
    apply CALL SITE actually reprograms a preserved reinjector on an MTU delta
    — is unit-testable without a privileged ioctl (#6097).
    - **Trigger compares `live_mtu`, not `mtu()` (#6097):** the reconcile fires
      on `desired_mtu != slow_path.status().live_mtu`, i.e. against the MTU the
      TUN is ACTUALLY programmed with. Using `mtu()` (the creation-desired
      value) instead would miss a STARTUP-`SIOCSIFMTU`-failure state, where the
      worker records `mtu()` at the creation jumbo value (e.g. 9000) while
      `live_mtu` fell back to 1500 and `degraded` is set: a day-2 reconcile
      whose desired still equals the creation MTU would then see
      `desired == mtu()` and SKIP forever, so a transient startup failure would
      never self-heal via reconcile (only on a config CHANGE or an xpfd
      restart). Comparing against `live_mtu` makes such a degraded live TUN
      retry the program on the next reconcile.
    - **Dedup / no ioctl storm:** the reconcile is deduped per distinct desired
      value (`last_slow_path_mtu_reconciled`; renamed from
      `last_slow_path_mtu_warned` since it now records reconcile ATTEMPTS, not
      warnings) so a steady-state reconcile loop over an unchanged snapshot does
      not re-issue the ioctl every tick. This dedup is what bounds the
      `live_mtu` trigger: when a program PERSISTENTLY fails, `live_mtu` never
      converges to `desired`, so the `desired != live_mtu` guard alone would
      retry every reconcile — the `desired == last_slow_path_mtu_reconciled`
      short-circuit holds the attempt to once per distinct desired value; the
      next DISTINCT desired retries. A failed `SIOCSIFMTU` on reconcile is
      non-fatal and, unlike the creation path, KEEPS the current live MTU
      (`SharedStatus::reprogram_mtu_status`; the running TUN retains whatever it
      was last programmed with rather than resetting to 1500), marks the path
      DEGRADED, and records the error — so `mtu()`, `live_mtu`, degraded state,
      and admission stay in agreement after every reconcile.
- **Reverse-path filter (#2378):** reinjected IPv4 replies arrive on the
  TUN but their reverse route still points at the real egress interface,
  so `open_tun` writes `conf/<dev>/rp_filter=0`. The kernel, however, uses
  the **maximum** of `conf/all/rp_filter` and `conf/<dev>/rp_filter`, so a
  non-zero `net.ipv4.conf.all.rp_filter` (strict=1 / loose=2 — a common
  Debian/Ubuntu default) overrides the per-device 0 and silently drops
  every reinjected IPv4 packet. The helper does NOT own host-global
  sysctls, so it does NOT mutate `conf/all/rp_filter`; instead `open_tun`
  reads `conf/all/rp_filter` once at bringup and emits a loud `xpf-ha:`
  warning (`rp_filter_all_warning`) when it is non-zero, instructing the
  operator to `sysctl -w net.ipv4.conf.all.rp_filter=0`. The Go reload
  path (`networkd.restoreSlowPathRPFilter`) re-asserts the per-device 0
  after a `networkctl reload` and mirrors the same `conf/all` warning
  (`warnIfAllRPFilterOverrides`). Both checks are bringup/reload-only,
  never per-packet.

### 3. Go Manager (`pkg/dataplane/userspace/manager.go`)

The Go side manages the Rust process lifecycle and feeds it configuration.

#### Snapshot Protocol

On every config commit, route change, or HA state transition, the
manager builds a `ConfigSnapshot` and sends it to the Rust process:

```
ConfigSnapshot {
    zones:           [{name, interfaces}]
    interfaces:      [{ifindex, name, mac, addresses, vlan_id, zone}]
    fabrics:         [{ifindex, name, mac, peer_mac, fib_ifindex}]
    neighbors:       [{ifindex, ip, mac}]
    routes:          [{prefix, next_hop, ifindex, table}]
    policies:        [{rule_id, from_zone, to_zone, src/dst, apps, action,
                       scheduler_name, inactive}]
    source_nat_rules:[{from_zone, to_zone, src/dst, interface/pool metadata}]
    static_nat_rules:[{name, from_zone, external_ip, internal_ip}]
    flow:            {allow_dns_reply, allow_embedded_icmp}
    # NAT address fields (static_nat external_ip/internal_ip and the NAT64
    # source-pool addresses) may arrive in canonical Junos host form carrying
    # a /32 (or /128) mask — the Go compiler keeps the prefix from
    # `match destination-address X/32` / `then static-nat prefix Y/32` and
    # address-range expansion stamps /32 on every produced pool IP. These are
    # exact host IPs, so the Rust parse strips the mask before IpAddr parsing
    # (mirroring the SNAT-pool idiom in nat/source.rs). Pre-#2122/#2123 the
    # bare IpAddr::from_str rejected the mask and silently dropped the rule /
    # pool entry (no translation, external IP not even recognized).
    map_pins:        {xsk_map, heartbeat_map, sessions_map}
    ha_groups:       [{rg_id, active, watchdog_ts}]
}
```

**Route-snapshot construction invariants (`buildRouteSnapshots`,
`pkg/dataplane/userspace/routes.go`).** The builder derives the `routes`
section from config statics, connected prefixes, and the kernel ip-rule
mirror (rib-group / next-table leaks), then folds the ip-monitoring
overlay. Four correctness invariants (#3770/#3772):

- **Dedupe by full identity.** The per-route dedupe key is
  `Table|Family|Destination|NextHops|NextTable|Discard|Preference`. A
  discard (blackhole) route and a normal route to the same prefix are
  DISTINCT decisions, and two routes differing only in preference (a
  static next-table route vs. its preference-0 ip-rule mirror) must both
  reach the Rust FIB so `sort_routes` (`fib.rs`) can apply its
  preference tie-break. Omitting Discard/Preference from the key
  (pre-#3770) silently dropped one of a colliding pair.
- **Deterministic emission order.** The final sort is `SliceStable` over
  a TOTAL order — Table, Family, Destination, then NextHops, NextTable,
  Discard, Preference. Once same-prefix routes coexist, a partial
  comparator + unstable sort let their order track non-deterministic
  build inputs (map iteration, kernel ip-rule order), churning the
  snapshot hash and re-installing the FIB for an unchanged config.
- **ip-rule read is fail-closed.** A `netlink.RuleList` failure is
  SURFACED as a build error (not swallowed), so the apply path retains
  the prior dataplane state instead of shipping a partial snapshot that
  drops every route-leak route for that family while the kernel/FRR leak
  path stays up. This mirrors #3731's surface-don't-swallow contract on
  the RuleAdd (write) side.
- **Overlay carries Static/1.** The ip-monitoring overlay route is
  emitted at route preference 1 (the documented `Static/1`,
  `PreferredRoute` contract in `pkg/config/types_system.go`), matching
  the FRR managed-section distance-1 render. An unparseable overlay
  destination is skipped (`canonicalRoutePrefix` returns `""`) rather
  than injected verbatim as a garbage FIB prefix.
- **ip-rule leak `NextTable` is family-specific (#3768 H6).** Each
  synthetic ip-rule leak snapshot targets the routing-instance table for
  the RULE's address family: an IPv4 leak points at `<inst>.inet.0`, an
  IPv6 leak at `<inst>.inet6.0`. The builder keys the table-id map on the
  bare instance name and derives the family suffix inside the AF_INET /
  AF_INET6 loop. The pre-#3768 emitter baked `<inst>.inet.0` once and
  reused it for the v6 pass, so an IPv6 leak targeted the instance's IPv4
  table; the Rust FIB keys `routes_v6` by `canonical_route_table(table,
  true) = "<inst>.inet6.0"`, so the v6 next-table recursion missed and
  the leaked IPv6 route blackholed. Defense-in-depth: the Rust recursion
  also `canonical_route_table`s the next-table name for the current
  family before lookup, and a per-resolution visited-table set rejects an
  A→B→A cross-table next-table cycle (formerly only a direct self-loop
  was caught, so a two-table cycle burned to `MAX_NEXT_TABLE_DEPTH`)
  (#3768 M5+M6, `userspace-dp/src/afxdp/forwarding/mod.rs`).

**Deterministic emission applies to EVERY map-backed snapshot builder, not
just routes (#3962).** Any builder that ranges a Go `map` and appends the
result into a `ConfigSnapshot` slice must iterate the map in a stable order,
because that slice is serialized into the JSON that `snapshotContentHash`
(`builder.go`) hashes for the duplicate-publish dedup. Go map iteration order
is randomized per run, so ranging `cfg.Security.Zones` (a
`map[string]*ZoneConfig`) directly produces a different wire byte order every
build for an UNCHANGED config — the hash differs, the reconcile never skips,
and the dataplane re-applies the config on every reconcile (needless
control-socket + dataplane work; a screen re-apply can also re-arm SYN-cookie
state). `buildScreenSnapshots` and its sibling `buildScreenMissingProfileRefs`
(`screens.go`, feeding `Screens` / `ScreenMissingProfiles`) now collect the
zone names, `sort.Strings` them, and range in sorted order — matching the
long-standing pattern in `buildZoneSnapshots` (`zones.go`) and
`buildSYNCookieMasterKey`. The syn-cookie master-key hash and all
zone-host-inbound builders already sorted; the NAT / tunnel / neighbor
builders range config SLICES (already ordered), so they were never affected.

**Dynamic-address feed overlay (#2049).** The snapshot's address books carry
the live `security dynamic-address` feed prefixes, not just the static
`security address-book`. The daemon joins each `address-name ... profile
feed-name` binding to the feed manager's current last-good snapshot
(`feeds.Manager.SnapshotForBindings`) and hands the result into the manager
via `SetFeedSnapshots` (mirroring the ip-monitoring `SetRouteOverlay`) at the
top of `applyConfigLocked`. `buildAddressBookTableWithFeeds`
(`policies.go`) then merges those CIDRs into the named book's content bucket
*before* ID assignment, so the feed-backed name emits an `AddressBookSnapshot`
row and `nameToID[name]` is populated — which lets `classifyPolicyAddresses`
route a referencing policy/NAT token into `source_book_ids` /
`destination_book_ids` instead of dropping it to a no-match literal. Because
the overlay lands in the hashed `AddressBooks` rows, a feed refresh (the
manager's `onUpdate` re-runs `applyConfig` against the *same* typed config)
shifts `snapshotContentHash` and the duplicate-publish gate republishes; an
identical refresh produces an identical hash and is correctly skipped. Per the
#2050 fail-safe, a fetch failure retains the last-good prefixes
indefinitely by default, so an enforced feed is normally never empty after its
first fetch; the only empty windows are the bounded startup-before-first-fetch
case and an explicit operator `hold-interval` drop (an empty book matches
nothing — fail-closed for an allowlist, the operator-opted fail-open for a
denylist).

**Classifier-map publish is a fail-closed transaction (#4959).** The manager
keeps a `snapshotBindingPlanKey` (`maps_sync.go`) over the worker/ring/
interface-binding/fabric plan. When a commit does NOT change that key — the
common **address-only** commit that edits a local address or an interface-NAT
address — `Compile` takes the lightweight `samePlanRefresh` path: it rewrites
the ingress / local-address / interface-NAT classifier BPF maps **in place**
(`syncUserspaceClassifierMapsFailClosedLocked`) rather than re-bootstrapping the
helper, then publishes the new `apply_snapshot`. The XDP shim reads those
classifier maps live (kernel-pass vs XSK-redirect, local-vs-interface-NAT
ownership) while `ctrl.Enabled == 1`. If the helper then **rejects** the
snapshot (a helper-side validation failure, or any transport error) it keeps
enforcing the previous-good snapshot — so the freshly-mutated maps would be a
generation *ahead* of the applied Rust snapshot with the shim still enabled: a
fail-**open** classifier/snapshot mismatch (wrong kernel delivery / wrong XSK
steering). The publish therefore routes through `publishSnapshotFailClosedLocked`
with the `samePlanRefresh` flag: on a same-plan publish error it disables
`ctrl` (`failClosedUserspaceCtrlMapLocked` → `Enabled=0`) so transit drops to
the kernel-only fail-closed posture until a subsequent good commit re-publishes
and re-enables it (`applyHelperStatusLocked`). The full **bootstrap** path
(binding plan changed) already programs `ctrl.Enabled=0` in
`programBootstrapMapsLocked` before the publish, so it is fail-closed without
extra work — which is why the fix keeps the same-plan fast path instead of
forcing every address edit through a bootstrap (that would clear binding rows
and blip transit on every successful commit). Distinct from the Rust-side
reconcile-ordering invariant (#2440/#2444/#3789) above: that one keeps the Rust
process fail-closed across teardown; this one keeps the **Go-owned classifier
BPF maps** consistent with the applied snapshot.

The **same fail-closed transaction covers the deferred-publish resume path.**
There are two `apply_snapshot` publish sites for a same-plan refresh. `Compile`
publishes synchronously in the steady state, but during **XSK startup** (the
liveness-probe window after the initial publish, before liveness is proven or
failed) it takes the `pendingXSKStartup` branch: it still mutates the classifier
maps **in place** (`syncUserspaceClassifierMapsFailClosedLocked`) with `ctrl`
already flipped to `Enabled=1` to probe, but **defers** the publish and returns
success. The status loop then completes the publish via `syncSnapshotLocked`
(`process_status.go`). An address-only commit landing inside that window is
exactly this case: the maps are already a generation ahead, so a rejected
deferred publish is the identical fail-open. `syncSnapshotLocked` therefore
routes its publish through `publishSnapshotFailClosedLocked` with
`mapsMutatedInPlace=true`. That flag is unconditional there because the
`pendingXSKStartup` branch is the **sole producer** of an unpublished
`m.lastSnapshot` ahead of `m.publishedSnapshot` — every other publish site
(`Compile` steady state, route-overlay, policy-scheduler, deferred-worker-arm)
advances `publishedSnapshot` only *after* a successful publish, so none can
strand a not-yet-mutated snapshot for the status loop to pick up. On a rejection
`ctrl` drops to `Enabled=0`; a successful deferred publish is transparent and
leaves the enable side to `applyHelperStatusLocked`.

#### Capability Check

The manager evaluates the active config to determine whether the userspace
dataplane can handle it. Unsupported userspace features fail closed or disarm
helper forwarding; userspace runtime traffic must not silently fall back into
the legacy kernel BPF pipeline.

The current supported/gated split is maintained in
[`userspace-dataplane-gaps.md`](userspace-dataplane-gaps.md). In broad terms,
the Rust path now owns stateful forwarding, zone/global policies, application
matching, interface-mode SNAT, DNAT, static NAT, NAT64, NPTv6, firewall
filters, flow export, TCP MSS clamping, configurable timeouts, VLAN handling,
route/neighbor lookup, and HA/session-delta ingestion.

The original #1374-#1381 userspace feature-gap blockers are closed. Remaining
eBPF retirement work is source-removal plumbing rather than feature admission:
#1451 is migrating the remaining operator/runtime surfaces off the legacy
`dataplane.DataPlane` bridge, #1473 keeps the retained XDP shim separate from
legacy fallback behavior, #1493 documents the userspace-only loader split,
#1476 owns the final source/generated-artifact deletion, and #1477 owns live
evidence for the exact deletion candidate.
SYN-cookie, port-mirroring, dataplane-event, and CoS/fairness live artifacts
belong in #1477 if the final source-removal candidate requires them.

Policy scheduler state is no longer a propagation gap: #1396 carries scheduler
state into the userspace snapshot and Rust policy evaluator, and the 2026-05-19
#1378 live artifact set validates hit-counter lifetime, strict missing-scheduler
commit behavior, and integration/failover evidence with
`test/incus/policy_scheduler_validate.py`. The **route-overlay** partial
republish (`PublishRouteOverlaySnapshot`, the ip-monitoring actuator) co-honors
this contract (#5328 A6-b2-F4): when the daemon hands it a live
`scheduler.ActiveState()` it rebuilds the published snapshot's `policies` /
`address_books` inactive bits from that map in the SAME publish — exactly as the
dedicated policy-scheduler republish (`UpdatePolicyScheduleState`) does — so a
route flap never ships a snapshot that reports success while the helper enforces
a stale schedule window. Previously the overlay only cached the map and inherited
the last-compiled policy sections, leaving the helper on stale bits until the next
scheduler tick or full apply. Both republish paths share one core
(`rebuildScheduledPolicySectionsLocked`), which re-applies the StableZoneID zone
quarantine's policy scrub after rebuilding `policies` from raw config (#6480): the
raw builder has no knowledge of the quarantine and would reintroduce a policy
referencing a quarantined zone, while the inherited `next.Zones` stays reduced —
a dangling policy->zone reference the Rust `UnresolvableZoneReference` preflight
rejects wholesale. Because the ip-monitoring actuator updates FRR *before* the
publish, that reject would strand the kernel/FRR on the new routes while userspace
kept the old FIB, unable to converge; the shared scrub keeps both paths in
lockstep so neither can drift. The shared core additionally **refuses the
republish outright when the passed `cfg` content-differs from the inherited
`m.lastSnapshot.Config`** (#6480), mirroring the route-overlay path's
`routeOnlyPublishHybrid` skew guard (#5680). This closes a fold-introduced
fail-open: during a config-skew window the daemon can reconcile the scheduler to
the newly promoted config B (the store promotes B before applying, and the apply
path continues on a transient dataplane error) while the OLD snapshot A is still
live. Rebuilding + scrubbing the policies against B's quarantine set while
inheriting A's `next.Zones` can drop a policy whose zone is still a live member of
A's zones — a snapshot the preflight *accepts* but whose missing rule lets traffic
fall through to the inherited default policy (a full Compile of B would instead
drop the quarantined zone and stay fail-closed). Refusing on skew retains the
prior snapshot and reconverges once B's full apply lands
(`m.lastSnapshot.Config == cfg`), under the existing #3780 retry semantics.
#1377 now preserves unusable pool-mode source-NAT rules in the snapshot and
fails closed at the `poll_descriptor.rs` source-NAT call sites for missing
pools, empty pools, invalid pool inputs, wrong-family-only pools, or allocator
failure. The current slice adds bounded helper-local persistent-NAT lease reuse,
allocator observability, and live-port exhaustion counters. #1449 records HA
persistent-lease behavior as a capability gate rather than lease replay; #1377
still owns helper-restart persistence and the documented mixed-backend rollback
boundary. #1386 landed
userspace buffer/status rendering, and #1380 now treats helper-published
capacity as the boundary for fill percentages instead of synthesizing
utilization from dynamic counters.

### 4. HA Cluster Integration

The userspace dataplane participates in the chassis cluster HA:

```
┌──────────────────┐     fabric link      ┌──────────────────┐
│  fw0 (PRIMARY)   │◄───────────────────►│  fw1 (BACKUP)    │
│                  │                      │                  │
│  xpfd ◄──────────── session sync ────────► xpfd       │
│    │             │                      │    │             │
│    ▼             │                      │    ▼             │
│  userspace-dp    │                      │  userspace-dp    │
│  [workers 0-5]   │                      │  [workers 0-5]   │
│  sessions: local │                      │  sessions: synced│
└──────────────────┘                      └──────────────────┘
```

**Session synchronization flow:**

1. Worker creates forward session → emits `SessionDelta::Open`
2. Coordinator collects deltas from all workers
3. xpfd drains deltas via control socket
4. Cluster sync sends deltas to peer over TCP fabric link
5. Peer xpfd pushes received sessions into userspace-dp
6. Peer workers install as "synced" sessions (no further replication)

**Failover handling:**

- VRRP detects primary failure (~60ms with 30ms intervals)
- New primary activates RGs → `UpdateRGActive(rg, true)`
- Workers start forwarding for activated RGs
- Synced sessions from peer are promoted on first packet match
- XDP shim session map allows immediate redirect for promoted sessions

**Fabric redirect:**

When a packet arrives on the backup node but the session owner is the
primary (or vice versa during failback), `try_fabric_redirect()` sends
the packet across the fabric link to the correct node.

## Performance Architecture

### CPU Layout (8 vCPU, 25G mlx5)

```
CPU 0: Worker 0 + NAPI (ge-0-0-1 queue 0, ge-0-0-2 queue 0)
CPU 1: Worker 1 + NAPI (ge-0-0-1 queue 1, ge-0-0-2 queue 1)
CPU 2: Worker 2 + NAPI (ge-0-0-1 queue 2, ge-0-0-2 queue 2)
CPU 3: Worker 3 + NAPI (ge-0-0-1 queue 3, ge-0-0-2 queue 3)
CPU 4: Worker 4 + NAPI (ge-0-0-1 queue 4, ge-0-0-2 queue 4)
CPU 5: Worker 5 + NAPI (ge-0-0-1 queue 5, ge-0-0-2 queue 5)
CPU 6: xpfd (Go daemon) + sync
CPU 7: main thread + io_uring + kernel
```

### Hot-Path Optimizations

| Technique | Impact | Description |
|-----------|--------|-------------|
| Lock-free forwarding | Critical | No mutexes on per-packet path; atomics for counters |
| FxHashMap sessions | ~1.7% CPU | Non-cryptographic hash for O(1) session lookup |
| Batched ring ops | ~2% CPU | Process 256 frames per RX batch, batch TX submissions |
| In-place UMEM rewrite | ~11% CPU saved | Same-binding forwarding without memcpy |
| Incremental checksums | ~1% CPU | RFC 1624 differential update vs full recomputation |
| Compile-time debug gate | ~0% overhead | `cfg!(feature = "debug-log")` compiles out all debug |
| Batched counters | ~0.5% CPU | Aggregate per-packet counts, flush atomically |
| Cached resolution | ~0.8% CPU | Reuse forwarding decision from session entry |
| NAPI busy polling | Latency | `SO_BUSY_POLL` reduces interrupt-to-userspace latency |

### Throughput Profile (23 Gbps, 12 streams)

| Component | CPU% | Notes |
|-----------|------|-------|
| poll_binding (user) | 22% | Main packet processing loop |
| memcpy (libc AVX-512) | 8% | Cross-UMEM frame copy (unavoidable) |
| XDP BPF programs | 7% | XDP shim + xdp_policy coordination |
| mlx5 driver (NAPI) | 12% | NIC receive/transmit processing |
| Interrupt handling | 4% | IRQ entry/exit |
| Syscalls (sendto) | 3% | AF_XDP ring kicks |
| Forwarding funcs | 8% | NAT, sessions, resolution, TX drain |
| Other kernel | 4% | TSC reads, XSK peek, fput |

### Scaling Characteristics

| Workers | RSS Queues | Throughput | Notes |
|---------|------------|------------|-------|
| 4 | 5 | 20 Gbps | CPU-bound (4 vCPU VM) |
| 6 | 6 | 23 Gbps | Near line rate (8 vCPU VM) |

Per-worker ceiling: ~4-5 Gbps (includes kernel NAPI overhead on same CPU).
RSS queue count should match worker count for optimal distribution.

### Sizing Headroom — the N-vCPU / N-queue / N-worker "no-headroom" regime

The "CPU Layout" above is the **recommended** sizing: an 8-vCPU VM running 6
workers leaves CPU 6 for the Go daemon (`xpfd`) and CPU 7 for the main thread +
kernel. That spare-core margin is what the `workers + 2` tuning guideline below
buys. When a VM is sized with **workers == vCPUs** there is no spare core, and
the box enters a *no-headroom* regime worth understanding before reading a
profile or sizing a shaper.

**The loss userspace cluster (`loss:xpf-userspace-fw0/fw1`) is exactly this
case: 6 vCPU = 6 mlx5 RX queues = 6 AF_XDP workers.** The dataplane is sized to
consume the entire machine. Consequences (all measured in #1752 on
`-P48 -p5210`):

- **All 6 cores run ~100% busy under load** (≈ `60% usr / 8% sys / 28% softirq`,
  ~0% idle). The workers busy-poll; NET_RX softirq for the same queues runs on
  the *same* cores (no separate IRQ core); and the Go control plane's GC +
  scheduler threads share those cores too (they do not get a dedicated one).
- **A configured CoS shape can sit ABOVE the box's forwarding ceiling, so the
  cap never becomes the binding constraint.** On this cluster, forwarding tops
  out CPU-bound at ~16 Gb/s with CoS enabled (the per-packet shaping code path
  still executes and costs ~19% CPU) and ~23 Gb/s with CoS disabled — both
  well under, e.g., a 24G `transmit-rate exact` scheduler. The shaper's `exact`
  cap only bites if the box can first push past it; here it cannot, so the
  observed rate is determined by the CPU ceiling rather than the configured
  shape.
- **"Headroom" does not exist at this sizing — there is no idle core to absorb a
  burst, a GC pause, or added per-packet work.** Freeing CPU on the hot path
  (e.g. #1753 session-refresh in-place mutation) buys margin but does not raise
  aggregate throughput when the binding constraint is elsewhere (the CoS path).

**To gain real headroom, scale the box, not the code:** add vCPUs **and** RX
queues **and** workers together (`ethtool -L <dev> combined N` + `workers N`),
keeping the `workers + 2` margin so the daemon and kernel get their own cores.
Reducing per-packet CPU cost only helps once the box is no longer at the
N/N/N ceiling.

> **Profiling caveat on this kernel/NIC:** `mlx5_core` ships compressed
> (`.ko.xz`), so `perf` rounds sample PCs in *unexported* static driver
> functions to the nearest *exported* symbol. On the loss cluster this
> mis-attributes real AF_XDP TX/RX wake `sendto()` cost (`mlx5e_xsk_wakeup` is
> static) to adjacent exported symbols such as the `mlx5_crypto_*_dek_*` family.
> This is not an open question: a `bpftrace` kprobe on
> `mlx5_crypto_modify_dek_key` recorded **0 calls** over 8-10 s of full load
> (while `mlx5e_napi_poll` recorded ~3.6M), i.e. those functions are not
> executing — there is **no crypto DEK work** on a plain forwarding path; the
> cost is the wake `sendto()` path. (What #1752 leaves open is the *separate*
> question of how much of that wake cost is recoverable — see #1754, not whether
> crypto is involved.) Takeaway: validate any kernel-symbol attribution with a
> `bpftrace` kprobe call-count before trusting the perf `%`.

## Configuration

```junos
system {
    dataplane-type userspace;
    dataplane {
        binary /usr/local/sbin/xpf-userspace-dp;
        control-socket /run/xpf/userspace-dp.sock;
        state-file /run/xpf/userspace-dp.json;
        workers 6;
        ring-entries 16384;
    }
}
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| workers | 1 | Number of AF_XDP worker threads |
| ring-entries | 1024 | RX/TX/fill/completion ring size per binding |
| binary | — | Path to Rust binary |
| control-socket | — | Unix socket for control protocol |
| state-file | — | JSON state persistence path |

**Tuning guidelines:**
- Set `workers` to match NIC RSS queue count (`ethtool -L <dev> combined N`)
- Set `ring-entries` to 16384 for ≥20 Gbps throughput.
  UMEM cost per binding at ring=16384:
    - mlx5 / native XDP: `reserved_tx (min(ring/2, 8192)) + 2 × ring_entries` = `8192 + 32768 = 40960 frames × 4 KB = 160 MB per binding`
    - virtio_net: `ring_entries + 2 × ring_entries` = `3 × 16384 × 4 KB = 192 MB per binding`
  `binding_frame_count_for_driver` in `userspace-dp/src/afxdp/bind.rs` is authoritative.
  At 8192, `iperf3 -P 12 @ 25 Gbps` sees 92-170K retrans/30s and median 16.9 Gbps due
  to kernel-side TX ring fill stalls (`ethtool -S` shows `tx_xsk_full` accumulating).
  Raising to 16384 dropped retrans to 0-1900/30s and lifted the median to 21.5 Gbps
  on the loss:xpf-userspace-fw test cluster (#774). **DO NOT raise to 32768** —
  measurement on the same workload showed regression to 11-18 Gbps with 17-37K retrans,
  likely TLB pressure + excess UMEM memset at bind.
- **Hugepages (REQUIRED for ring ≥ 16384)**: UMEM mapping tries `MAP_HUGETLB` (2 MB
  pages) first, falls back to `MADV_HUGEPAGE` (advisory, kernel may or may not promote).
  At ring=16384 × 4 KB pages = 40960 TLB entries per binding × 6 bindings = 245K TLB
  entries — that's larger than a typical CPU's TLB can hold, and throughput will stall
  in TLB-miss latency. With 2 MB hugepages the same UMEM needs ~480 TLB entries,
  fitting comfortably in the iTLB/dTLB.

  **Reserve via `/etc/sysctl.d/99-xpf-hugepages.conf`:**
  ```
  vm.nr_hugepages = 600
  ```
  Apply with `sysctl --system` (or reboot). 600 × 2 MiB = 1.2 GiB covers one NIC's
  UMEM at ring=16384. Verify with `grep HugePages_ /proc/meminfo` — `HugePages_Total`
  must be ≥ 560 before xpfd starts, else `MAP_HUGETLB` will fail silently and the
  daemon will fall back to THP which is not guaranteed to promote all pages.

  **Measurement on loss:xpf-userspace-fw0 (8 GiB VM, kernel 7.0.0-rc7, mlx5 ConnectX):**
    - ring=8192 (no hugepages needed): median 16.9 Gbps, stddev 1.7
    - ring=16384 without hugepages: median 20.4 Gbps, stddev 1.7
    - ring=16384 with 600 hugepages: **median 22.1 Gbps, stddev 1.5** ← campaign target
- Ensure VM has enough vCPUs: workers + 2 (daemon + kernel headroom)
- Ensure VM has enough RAM: `workers × bindings × 160 MB + 2 GB` base (at 16384 ring,
  mlx5 driver; 192 MB for virtio_net)

### Config-snapshot protocol version (#5488)

Every `apply_snapshot` and `bump_fib_generation` body carries a `version`
field. Two constants define it and **MUST be bumped in lockstep**:

- **Go emitter** — `ProtocolVersion` in
  `pkg/dataplane/userspace/protocol.go`, stamped onto every snapshot the
  builder produces.
- **Rust consumer** — `CONFIG_SNAPSHOT_PROTOCOL_VERSION` in
  `userspace-dp/src/protocol/control.rs`.

Both mutating verbs gate on **EXACT equality**, not `>=`
(`userspace-dp/src/server/handlers/snapshot.rs`, `apply` and `bump_fib`):
a helper at any other version refuses the body before touching dataplane
state, rather than decoding it under its own, narrower contract. The
lockstep is pinned by `TestSnapshotProtocolVersionLockstepWithRust`,
which parses the Rust constant rather than mirroring it in a comment.

**What the version means.** It is the meaning of the snapshot message,
not a feature inventory. Bump it whenever a change makes an older reader
interpret the SAME bytes differently — in particular whenever a new field
becomes authoritative over an existing one. A field that is purely
additive *in meaning* (an old reader that ignores it still enforces
exactly what it enforced before) does not need a bump; a field that
changes what a rule COVERS does.

**Why it is at 4.** #4626 gave a scoped global policy a zone-SET scope in
the plural `match_from_zones`/`match_to_zones` fields, made them
authoritative, and left the singular `match_from_zone`/`match_to_zone`
carrying only the FIRST element — but did not bump the version. A
pre-#4626 helper at the same advertised version 3 therefore accepted the
snapshot, read only the singular field, and NARROWED a multi-zone global
`deny` to one zone, letting the dropped zones' traffic reach a
lower-precedence permit. That is the dangerous direction: a handshake
that reports agreement while the two sides disagree about the message.
The invariant #5488 records is that **a compatibility extension which
changes deny/reject COVERAGE must not be silently ignorable under an
unchanged protocol version.**

**The bump is paired with a fail-closed gate.** On its own, a bump only
makes an old helper *refuse* the snapshot — and a refused snapshot leaves
that helper ARMED on its previous-good image, still forwarding, with the
newly committed deny never installed. So the version bump is paired with
`ensureScopedGlobalZoneSetProtocolLocked`
(`pkg/dataplane/userspace/manager_compile.go`), a required-protocol gate
in the same class as the policy-scheduler and persistent-source-NAT gates
(#2138): when the committed config carries a policy whose scope holds
more than one zone on a side and the running helper reports a
`ConfigSnapshotProtocolVersion` below `ProtocolVersion`, the daemon
DISARMS the helper (`set_forwarding_state{armed:false}`) and the commit
ABORTS with `ErrScopedGlobalZoneSetProtocolIncompatible`, which is
registered in `requiredProtocolGateSentinels`. The lenient-load doctrine
(#1960) is unchanged: a boot or peer-sync apply of an already-persisted
config disarms and logs rather than bricking the node; only the
operator-facing commit path surfaces the abort.

The gate is keyed on the multi-zone **shape**, not the action, so it
covers both directions of misrepresentation — narrowing a `deny`/`reject`
(fail-open) and narrowing a `permit` (a fail-closed correctness break). A
**single-zone** scope emits `singular == the one zone` and an unscoped
global emits neither side, so neither can be narrowed by a singular-only
reader and neither is gated; that keeps the disarm blast radius to
exactly the misrepresentable population.

If the disarm ITSELF fails, the helper is still armed on its
previous-good snapshot — and on a publish path whose classifier BPF maps
were already mutated in place, the shim would be redirecting transit to
XSK against maps a generation ahead of what the helper is enforcing. So
`disarmSnapshotProtocolFailClosedLocked` additionally drives
`userspace_ctrl` to `Enabled=0` on exactly the two paths that pass
`mapsMutatedInPlace=true` to `publishSnapshotFailClosedLocked` (Compile's
`samePlanRefresh` and `syncSnapshotLocked`), dropping transit to the
kernel-only fail-closed posture. The wrap preserves the gate sentinel, so
the commit still aborts.

**Residual: this version is node-LOCAL (#6650).** The snapshot protocol
version governs the daemon↔local-helper socket only; it never crosses the
cluster heartbeat. In a mixed-version HA pair, node A (v4) commits a
multi-zone scope, its own gate does not fire because its own helper is
v4, and `pushCommittedConfigToPeer` ships the config TEXT to node B —
whose v3 daemon compiles it and narrows the deny against its own v3
helper. That is the same fail-open relocated from "old helper" to "old
peer node", and it is NOT closed here: closing it needs a scope signal on
the config-sync/heartbeat wire. Tracked as #6650.

### Control-socket request size cap (#2523, #2744)

Each control-socket request is a single newline-delimited JSON body. The
helper reads it into memory before any schema validation can run, so a
malformed or compromised local caller could otherwise stream an
unbounded line and force a runaway read allocation. Both sides therefore
bound a single request to a fixed ceiling, **in lockstep**:

- **Rust receiver** — `MAX_CONTROL_REQUEST_BYTES` in
  `userspace-dp/src/protocol/control.rs`. The accept loop reads at most
  `cap + 1` bytes via a `take`-bounded `read_until`; a body that hits the
  cap without a terminating newline is rejected before decode
  (fail-closed: daemon alive, stale config retained, one log line).
- **Go sender** — `MaxControlRequestBytes` in
  `pkg/dataplane/userspace/process.go`. A pre-flight check serializes the
  request and, if it would exceed the cap, returns an actionable
  operator-facing config error **at apply time** instead of letting the
  helper reject it silently after the config is already committed.

**Sizing (#2744):** the dominant scaling dimension is NOT policy/NAT/route
count (a hand-authored config is a few MB) but **dynamic-feed-backed
address books** — `AddressBookSnapshot.prefixes_v4/v6` carry feed
prefixes inline as CIDR text (`buildAddressBookTableWithFeeds`,
`pkg/dataplane/userspace/policies.go`), bounded only by a per-line
scanner cap in `pkg/feeds`, not a total-entry cap. The original #2523
ceiling was 16 MiB and could reject a *legitimate* feed-heavy
`apply_snapshot` (~500K IPv6 CIDRs ≈ 20+ MiB). #2744 raised the ceiling
to **64 MiB** — `64 MiB / ~45 B per IPv6 CIDR ≈ 1.4M prefixes`, well
above realistic large threat-intel feeds while still bounding a single
request's read allocation to a fixed DoS guard. **The two caps MUST stay
identical**; the relationship is pinned by
`TestControlRequestCapLockstepWithRust` (Go) and the
`legitimate_feed_above_old_16mib_cap_is_now_accepted` /
`request_above_new_cap_is_still_rejected` fail-on-revert tests (Rust).

### Control-socket round-trip deadline (#4036)

The Go sender (`requestDetailedLocked`, `pkg/dataplane/userspace/process.go`)
sets a single read/write deadline on the control connection covering the
whole round-trip: write the request body, then block on the helper's JSON
response. The helper reads the whole body, decodes it, **applies** it, and
only then writes the response, so the deadline must cover the helper's apply
time — not just the socket transfer.

The deadline is **sized to the serialized request length** rather than fixed.
A fixed 3s was correct for the small frequent requests but too short for a
large `apply_snapshot`: at the 64 MiB ceiling the helper must decode ~1.4M
feed-backed address-book CIDRs, build the address-book LPM tables, plan
bindings, and reconcile AF_XDP before replying, which can exceed 3s. Under
the fixed deadline Go's `Decode` timed out and reported the apply **FAILED**
while the helper had actually applied the snapshot and the dataplane was
forwarding live with the new config — a spurious commit failure that could
trigger a needless rollback/retry or a false HA dp-failure.

`controlRoundtripDeadline(bodyLen)` computes the deadline: it keeps the
historical **3s base** for any sub-1-MiB request (so the 1/s status poll and
the small forwarding/HA/session requests are byte-for-byte unchanged and the
poll stays responsive per the #182 contention discipline) and adds **1s per
mebibyte** on top, capped at **120s**. At the 64 MiB request ceiling this is
`3s + 64s = 67s`, comfortably under the cap — generous enough for a legitimate
feed-heavy apply while still bounding a genuinely-hung helper (the caller holds
`m.mu` across the round-trip, so an unbounded wait would freeze status polls
and session installs). The length is the same `len(body)` the #2744 pre-flight
already serializes, so no extra marshal. The dedicated session-sync socket
(`requestSessionSync`) keeps the flat 3s: it carries only small per-session
installs; the bulk session export/drain paths run over this main control
socket and so already get the scaled deadline. Sizing math and a fail-on-revert
round-trip (a slow-but-successful large apply that trips a fixed 3s but not the
scaled deadline; a hung helper that still times out) are pinned by
`control_socket_deadline_4036_test.go`.

## Limitations and Mixed Boundaries

This section is a high-level architecture note. The authoritative current gate
is [`userspace-dataplane-gaps.md`](userspace-dataplane-gaps.md).

**Still explicitly tracked for eBPF retirement:**
- Source NAT pool mode: userspace-v1 deterministic pool selection and
  fail-closed runtime handling for missing pools, empty pools, invalid pool
  inputs, wrong-family-only pools, and allocator failures have landed.
  Helper-local non-HA per-pool `persistent-nat` lease reuse and pool
  allocation/exhaustion counters have landed. #1449 closes HA behavior as an
  explicit userspace capability gate because persistent leases are not
  synchronized. Helper-restart reset and mixed-backend selector parity are
  documented contracts, not active #1377 blockers.
- SYN-cookie flood protection closeout: bounded SYN-ACK/RST TX,
  root-auth-derived snapshot key publication, fail-closed missing-secret
  behavior, status counters, and gate removal are wired. Any final live
  HA/flood artifact belongs with #1477 on the source-removal candidate.
- RFC 2697/2698 three-color policer closeout: #1375 now preserves
  token/counter state across compatible in-process snapshot refreshes and
  admits the reviewed color-blind `then discard` runtime slice. Sharded/packed
  state, HA/restart continuity, non-drop color actions, and broader perf
  evidence are production follow-ups, not active feature-gap blockers.
- Port mirroring closeout: #1376 now has bounded userspace runtime admission,
  with final mirror-fidelity or pressure-survival artifacts belonging in #1477
  if the source-removal candidate needs them.
- Dataplane event closeout: #1379 is closed for policy-deny, screen-drop, and
  filter-log emission. Final live syslog proof, if required, belongs with
  #1477.
- `show system buffers` BPF-map display retirement: #1380 is closed for the
  current helper schema. Userspace mode uses helper status, preserves the
  active-session footer, renders session/flow utilization from Rust-owned
  helper denominators, and keeps neighbor values as counters until Rust owns a
  bounded neighbor-cache capacity.

**Handled outside the AF_XDP forwarding fast path:**
- ARP, NDP, local management traffic, and other kernel-owned packets are passed
  to cpumap/kernel handling.
- IPsec/XFRM and GRE transit use kernel/pass-through or tunnel-specific
  handling where required. Host-terminated IPsec (ESP/AH/IKE) is
  recognized by `stage_ipsec_passthrough_check` (Stage 11) and reinjected
  toward the kernel XFRM stack. Stage 11 runs BEFORE the per-zone
  host-inbound admission gate; raw ESP/AH and the IPsec data plane are
  **exempt** from it (the SA is the authorization — ratified #3616 Option
  A), but a **NEW inbound IKE initiation is GATED** on the ingress zone's
  `system-services ike`/`ipsec` (#4323 Option B). `classify_ipsec_admission`
  splits the two by the ISAKMP Responder SPI: an all-zero Responder SPI is
  the first packet of a new exchange (gated); a set Responder SPI is only
  admitted as a reply of a LIVE exchange — #6471: on the secondary path
  (DNAT-to-self / GRE-inner) a set-SPI packet must match a seeded exchange
  (Initiator SPI, peer IP, local IP), installed only AFTER the gate admits a
  zero-Responder initiation, with a 4096 cap + 24h sliding idle reap, so a
  forged set-SPI packet can no longer mint its own admission (the pre-#6471
  text here called every set-SPI packet unconditionally exempt). A denied NEW IKE
  is a silent drop (`host_inbound_denied_packets` +
  `RT_FLOW_CLOSE_REASON_HOST_INBOUND`) so it never reaches the local IKE
  daemon. The PRIMARY host-inbound enforcement for direct IPsec-to-self is
  the kernel nftables chain (`pkg/daemon/daemon_nft.go`), with the same
  ESP/AH-global-accept + NEW-IKE-gate + established-first semantics; the
  #4323 gate brings the SECONDARY AF_XDP path (DNAT-to-self, native-GRE
  inner) to parity. The synthetic Stage-11 reinject decision keeps
  `local_ifindex` = 0 (a non-zero value would divert it into the GRE
  local-tunnel-delivery channel and mis-deliver IPsec-to-self); the #4323
  gate is a separate admit check BEFORE the reinject, never a routing-
  decision change. See `userspace-dp/src/afxdp/forwarding/README.md` and
  `docs/research/3616-ipsec-host-inbound/plan.md`.
- Packets failing forwarding resolution can enter the bounded slow path,
  but ONLY for the slow-path-eligible dispositions: `LocalDelivery`,
  `NoRoute`, `MissingNeighbor`, and `NextTableUnsupported`
  (`ForwardingDisposition::is_slow_path_eligible`, the single source of
  truth shared by the filtered `maybe_reinject_slow_path` wrapper and the
  trailing chokepoint in `poll_binding_process_descriptor`). `PolicyDenied`,
  `HAInactive`, and `DiscardRoute` are NOT eligible — reinjecting them
  would hand the packet to the kernel FIB and silently bypass a zone-policy
  DENY / HA gate / discard route (#1913). They are dropped (counted by
  `record_forwarding_disposition`, recycled) instead. The raw
  `maybe_reinject_slow_path_from_frame` primitive does NOT apply the
  filter; its two intentional unfiltered callers (the FabricRedirect-Owned
  fallback in `tx/dispatch/mod.rs` and the ForwardCandidate build-failure
  fallback in `tx/dispatch/slow_path.rs`) own the eligibility decision.
  Note that `MissingNeighbor` IS slow-path-eligible, so a denied flow
  must be converted to `PolicyDenied` BEFORE it reaches the gate: the
  MissingNeighbor arm has its own policy evaluation (the main
  deny→PolicyDenied conversion lives only in the ForwardCandidate
  branch) and converts a deny to `PolicyDenied` — dropping and recycling
  without seeding a session or buffering for neighbor retry — so a denied
  unresolved-neighbor cold-path packet is not slow-path-reinjected (#1913).
  This deny check runs at the TOP of the MissingNeighbor arm — before the
  negative-cache fast-fail / shared-resolver enqueue AND before the kernel
  ARP/NDP probe — so a denied flow never induces neighbor-resolution
  network traffic on the egress interface, never enqueues a resolver
  probe, and never takes the dead-host fast-fail recycle path (it would
  otherwise re-probe on every packet, since denied frames are not
  buffered).
