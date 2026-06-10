# userspace-dp/src/afxdp/

Primary #1373 AF_XDP forwarding path. New dataplane hot-path work belongs here
or in the adjacent userspace modules unless a legacy eBPF regression/rollback
need is explicit.

The hot path. Coordinator + per-worker threads + UMEM + RX/TX/fill/
completion rings + frame parsing + session glue + neighbor cache + HA
sync.

## Submodules

- `coordinator/` — spawns and supervises workers, owns the binding
  plan, tracks worker liveness (`#925`), publishes status snapshots,
  receives lifecycle commands from the control socket. `mod.rs` is the
  single entry that owns shared state Arcs; `worker_manager.rs` keeps
  the per-worker handle table.
- `worker/` — the per-worker poll loop (`mod.rs` runs the dispatch).
- `poll_stages.rs` — sibling of `worker/`, not inside it. Holds the
  per-packet pipeline stages extracted in #946 Phase 1.
- `frame/` — packet parsing (L2 / L3 / L4), checksum helpers, TCP MSS
  clamp. `tests.rs` was relocated out of `mod.rs` in #1046 Phase 1.
- `umem/` — UMEM allocator, fill ring, completion ring. Frames are
  4 KB (`UMEM_FRAME_SIZE = 4096`); index is `addr >> 12`.
- `tx/` — TX ring management, batched enqueue, TSO segmentation
  (`tx/tcp_segmentation.rs` after PR #1199), per-binding TX counters.
- `cos/` — Class-of-Service scheduler: token-bucket admission, MQFQ
  active-bucket selection, fair-share lease (#1229 Phase 6 v8). See
  `docs/per-5-tuple/state.md` for the architectural ceiling.
- `forwarding/` — FIB lookup, next-hop selection, VLAN/GRE encap.
- `event_emit.rs` — fixed-size, non-blocking RT_FLOW event producers
  for userspace policy-deny, screen-drop, logged PBR filter hits, and
  non-PBR input/output/lo0 filter logs. Output filter-log identity is
  carried through live TX selection and cached forwarding so flow-cache
  hits emit the same compiled filter/term/action metadata as live paths.
  Terminal output `discard`/`reject` terms are carried in the TX selection
  descriptor and drop before enqueue; filter-log deny records must not
  describe traffic that still forwards. DSCP-matched input/output filters
  are intentionally not flow-cached because DSCP is packet metadata, not
  part of the session cache key; session hits re-evaluate DSCP-sensitive
  input filters per packet.
  Producers must use the event-stream worker handle so rate limiting,
  queue-budget accounting, replay, and daemon callback ACK behavior stay
  centralized in `event_stream/`.
- `session_glue/` — bridges the userspace session table back to the
  BPF session map mirror so the CLI / GC see the same sessions.
- `types/` — shared structs: `BindingPlan`, `BindingStatus`,
  `WorkerRuntimeAtomics`, `SharedCoSQueueLease`, `BatchCounters`, …

## Worker command-queue poison policy (#1790 → #1807)

Coordinator↔worker commands flow through per-worker
`Mutex<VecDeque<WorkerCommand>>` queues. A worker panic while holding
the lock (contained by the #925 supervisor) poisons the mutex. The
uniform policy lives in `worker_queue.rs` and is mandatory for every
access — do NOT call `.lock()` / `.try_lock()` on these queues
directly:

- `lock_recover` / `try_lock_recover` recover a poisoned lock via
  `into_inner`, **clear the poison** (restoring the fast unpoisoned
  path), and bump the recovery counter surfaced as
  `xpf_userspace_worker_command_queue_poison_recoveries_total`.
- The recovered deque holds the **committed prefix** of every completed
  push — a panic between the pushes of a multi-push section leaves
  exactly the commands pushed before it. Commands are individually
  self-contained, so consumers tolerate partial batches; discarding the
  deque would lose acknowledged HA/session commands.
- `try_lock_recover` keeps WouldBlock as a skip (`None`) — only the
  Poisoned arm changes behavior.

History: #1790 added recover-without-clear at the five coordinator
ha.rs sites; #1807 extended recovery to every producer/consumer site
(worker poll peek, `apply_worker_commands`, session replication,
activation prewarm, tunnel install/drain-wait, cross-binding shaped-TX
redirect) and retrofitted the coordinator sites onto the shared
helpers. Before #1807 a single poisoned queue made the worker
permanently deaf (poison read as "no commands") while producers
silently dropped or, for the tunnel drain-wait, spun to timeout.

## Hot-path constants

- `RX_BATCH_SIZE = 64`
- `TX_BATCH_SIZE = 64`
- `MAX_RX_BATCHES_PER_POLL = 4`
- `FILL_WAKE_SAFETY_INTERVAL_NS = 500_000` (lost-wakeup safety net)
- `HEARTBEAT_GRACE_PERIOD_NS = 6 * 1_000_000_000`

These are paired with cache-footprint and CoS-quantum invariants —
const-asserts catch unintentional changes.

## CPU pinning

`worker::pin_current_thread(worker_id)` (in `neighbor.rs`) honors the
inherited systemd `CPUAffinity=` mask. Worker N pins to the N-th
*allowed* CPU in that mask, so `CPUAffinity=2 3 4 5` puts workers
0..3 on CPUs 2..5 — outside the default mask but inside the unit's.
Don't revert to absolute-index pinning; the `CPUAffinity=` test catches
it explicitly.

## Reading order

`coordinator/mod.rs` for ownership and lifecycle, then
`worker/mod.rs` for the dispatch, then the sibling `poll_stages.rs`
for the per-packet stages, then peer modules as needed.
