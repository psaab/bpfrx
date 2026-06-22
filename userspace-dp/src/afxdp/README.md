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
  per-packet pipeline stages extracted in #946 Phase 1. The screen and
  SYN-cookie stages decide the L3 offset (14 vs 18) on tag PRESENCE
  (`meta.ingress_vlan_present != 0`), not `vlan_id > 0` — 802.1p
  priority-tagged frames carry a real 802.1Q tag with VID 0, so a
  VID-based test would mis-read the IP header at offset 14 (#2145).
- `frame/` — packet parsing (L2 / L3 / L4), checksum helpers, TCP MSS
  clamp. `tests.rs` was relocated out of `mod.rs` in #1046 Phase 1.
  `headers.rs` holds the consolidated outer-header serializers (#1440).
  The Ethernet writers emit an 802.1Q/802.1ad tag on tag *presence*
  via `TxVlanTag` (#2149), not `vlan_id > 0`: a tag is serialized when
  the VID is non-zero OR the PCP/DEI bits are set, so an 802.1p
  priority-tagged VLAN-0 frame (real tag, VID 0, PCP != 0) keeps its
  priority instead of collapsing to untagged. The reflected
  local-origin ICMP error path (`icmp.rs`) carries the inbound TCI
  (PCP + DEI + VID) and TPID through verbatim, so a priority-tagged or
  802.1ad-tagged inbound packet is reflected with its tag intact;
  untagged ingress still falls back to the egress interface's
  configured VID. The egress *config-driven* builders (forwarding,
  GRE/WG outer, TSO) still take a bare VID where VID 0 == untagged is
  the intended semantic (no PCP source on those paths) — `From<u16>`
  reproduces the legacy bytes exactly.
- `umem/` — UMEM allocator, fill ring, completion ring. Frames are
  4 KB (`UMEM_FRAME_SIZE = 4096`); index is `addr >> 12`.
- `tx/` — TX ring management, batched enqueue, TSO segmentation
  (`tx/tcp_segmentation.rs` after PR #1199), per-binding TX counters.
  - `tx/dispatch/` — the per-tick forwarding dispatcher
    (`enqueue_pending_forwards`). **Recycle-on-every-path invariant
    (#2208):** the ingress descriptor is read directly from ingress
    UMEM (the RX ring already released it), so `recycle_ingress_frame`
    — pushing `source_offset` to `pending_fill_frames` → the fill ring
    — is the SOLE path that returns the frame to circulation. Every
    per-request exit MUST recycle exactly once: the loop finalizer does
    this (`if !retained_source_frame`), and `retained_source_frame` is
    true ONLY on the in-place-rewrite branch (where the descriptor IS
    the TX frame and is recycled by `PreparedTxRecycle::fill_on_slot`
    on completion). Exception/build-failure branches must FALL THROUGH
    to the finalizer, never `continue` past it — a bare `continue`
    leaks the descriptor (per-packet UMEM-pool drain → worker stall
    under TX congestion). The two enqueue-failure sites also set
    `build_failed=true; fallback_to_slow_path=true` so the finalizer's
    `handle_forward_build_failure` reinjects the frame to the slow path;
    the two oversized sites set `build_failed=true` only (the frame is
    undeliverable — drop-and-recycle, no reinject).
    **Egress-MTU PTB (#2301):** for a forwarded frame the TCP-segmentation
    path did NOT handle (non-TCP, TCP seg-miss, non-segmentable TCP) the
    dispatcher makes an egress-MTU decision (`icmp_ptb.rs`,
    `forwarded_egress_mtu_decision`) BEFORE building the oversized frame.
    When the L3 payload exceeds the egress MTU and the sender forbade
    fragmentation (IPv4 DF) or it is IPv6, it generates an ICMP
    Frag-Needed (v4 type 3 code 4, next-hop MTU per RFC 1191) / Packet
    Too Big (v6 type 2, MTU per RFC 4443) back out the ingress interface
    and drops the oversized original (`mtu_signalled` keeps
    `retained_source_frame` false → the finalizer recycles the ingress
    descriptor; a suppressed/unbuildable reply is the fail-closed silent
    drop). NAT64 / native-tunnel encap are skipped (their on-wire L3 size
    differs from the source frame; the descriptor-capacity oversized
    backstop still applies). The reply is built inside the
    `target_binding` borrow and enqueued onto `ingress_binding` once that
    borrow ends.
- `icmp_ptb.rs` — #2301 PMTUD error generators for the generic
  forwarder: the egress-MTU decision plus the ICMPv4 Frag-Needed /
  ICMPv6 Packet-Too-Big builders (MTU in the body). Mirrors
  `icmp.rs`'s reflected-error shape (L2 reflect + ingress-sourced outer
  IP + quoted inbound packet) but sets the MTU field; reuses the shared
  header/checksum helpers and the RFC error-suppression gate
  (`reject_icmp_reply_suppressed`, `is_non_first_fragment`,
  `dest_is_multicast_or_broadcast`). Kept separate from `icmp.rs` so the
  diff stays additive. #2314: the PTB gate (`ptb_reply_suppressed`) now
  also drops PTBs triggered by a multicast/broadcast-destined datagram
  (RFC 1812 §4.3.2.7 / RFC 4443 §2.4(e)), sharing the
  `dest_is_multicast_or_broadcast` predicate (`frame/inspect.rs`) with
  `icmp.rs`'s `can_generate_icmp_error_reply` so the PTB, reject, and
  Time Exceeded paths agree on the L3 destination test. #2325: the same
  gate now also drops PTBs triggered by a datagram delivered as a
  link-layer (L2) broadcast/multicast frame, giving the PTB path the same
  L2+L3 suppression the reject / Time-Exceeded path already had — both
  call the shared `l2_dst_is_group_or_broadcast` predicate
  (`frame/inspect.rs`, the IEEE I/G group bit on the destination MAC's
  first octet; all-FF broadcast is a group address). No new counter: a
  suppressed PTB is folded into the existing fail-closed silent-drop path
  (the oversized original is still dropped via `mtu_signalled`). #2328: a
  PTB that IS generated is now classified by its OWN egress 5-tuple through
  the shared `classify_generated_reply` (`tx/cos_classify.rs`) before the
  enqueue in `tx/dispatch/mod.rs`, exactly like the ICMP/ICMPv6 Time
  Exceeded (#2238), policy-`reject`, and SYN-cookie generators — so an
  output firewall filter `discard`/`reject` / CoS forwarding-class / DSCP
  rewrite keyed on the generated ICMP fires, and the resulting
  `cos_queue_id`/`dscp_rewrite` drive the PTB TxRequest (pre-#2328 it was
  `None`/`None`). An output-filter drop lands on `ptb_output_filter_drops`;
  a parse failure of the built bytes fails CLOSED on
  `generated_reply_classify_parse_errors` (§6.2), never leaking the PTB
  past an output `discard`.
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
