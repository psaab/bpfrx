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
  - **Worker-liveness clock (`#2332`, Rust sibling of `#1792`):** the
    binding-readiness gate in `coordinator/refresh_bindings.rs` MUST use
    a monotonic-clock freshness verdict, never the wall clock. Each
    worker stamps its heartbeat slot with `monotonic_nanos()`
    (CLOCK_MONOTONIC); `BindingLiveState::snapshot()` computes
    `heartbeat_fresh` via `bpf_map::heartbeat_fresh_mono(last_ns,
    now_mono)` in the same monotonic domain and carries the verdict on
    `BindingLiveSnapshot`. The `last_heartbeat: DateTime<Utc>` field is
    back-projected onto the wall clock for operator display ONLY — a
    forward CLOCK_REALTIME step (NTP `makestep`, VM pause/resume) would
    poison any wall-clock age and falsely mark a healthy worker unready,
    which the control plane can read as a hung worker and turn into a
    spurious VRRP failover / route withdrawal.
- `worker/` — the per-worker poll loop (`mod.rs` runs the dispatch).
- `parser.rs` — pure control-plane parsers (#947) for the two L2/L3
  learning shapes that drive the dynamic-neighbor cache: ARP replies
  (`classify_arp`) and IPv6 Neighbor Advertisements
  (`parse_ndp_neighbor_advert`). The poll-stage learn site
  (`poll_stages.rs::stage_link_layer_classify`) inserts the parsed
  `(ifindex, ip) -> mac` binding into `dynamic_neighbors` AND the kernel
  neighbor table, so these parsers are a MAC->IP write primitive — they
  MUST fail closed on untrusted input.
  - **MAC-change invalidation (`#3048`):** the learn goes through
    `insert_if_changed`, NOT a plain `insert`, so a MAC change observed
    directly on the wire (e.g. an upstream gateway VRRP failover whose
    ARP reply / NDP NA traverses our XSK) advances the neighbor
    `mac_change_epoch` and evicts the now-stale cached `dst_mac`. A plain
    insert would write the new MAC first and then SHADOW the kernel-monitor
    RTM_NEWNEIGH that follows `add_kernel_neighbor` (the monitor would see
    `prior == new` and not bump), leaving the flow cache stale until session
    expiry. See `docs/flow-cache-simplification.md` "Neighbor MAC-change
    invalidation".
  - **Logical-ifindex keying (`#2370`):** the `ifindex` in that
    `(ifindex, ip)` key is the LOGICAL (L3) ifindex, NOT the physical
    ingress port. For a frame arriving on a VLAN sub-interface,
    `meta.ingress_ifindex` is the parent/bind port and
    `meta.ingress_vlan_id` selects the logical interface;
    `stage_link_layer_classify` resolves `(parent, vlan) -> logical` once
    via `resolve_ingress_logical_ifindex` and keys BOTH the
    `dynamic_neighbors` insert and `add_kernel_neighbor` under it. This
    matches the forwarder, which looks up neighbors by the connected-route
    (logical) ifindex (`lookup_neighbor_entry`; routes are stored under
    `iface.ifindex` in `forwarding_build/interfaces.rs`). Keying the
    insert by the physical parent (the pre-#2370 bug) made the just-learned
    entry invisible to the lookup on VLAN sub-interfaces → an avoidable
    MissingNeighbor cold-path probe and first-packet latency. Untagged
    interfaces resolve physical == logical (unchanged); a physical port
    with no matching logical sub-interface falls back to the physical
    ifindex (no drop). Two VLANs on one physical port resolve to distinct
    logical ifindexes, so a same-IP-different-subnet neighbor never
    collides in the cache.
  - **Same SSOT for zone / screen / generated-ICMP keying (`#3021` /
    `#3022` / `#3026`):** every per-ingress map keyed by the LOGICAL unit
    ifindex must resolve `(parent, vlan) -> logical` through
    `resolve_ingress_logical_ifindex` before indexing — not pass the raw
    `meta.ingress_ifindex`. `ifindex_to_zone_id` is keyed by the logical
    unit (`forwarding_build/interfaces.rs:76`); the physical parent ifindex
    only ever inherits its FIRST sub-interface's zone (lines 77-86), so a
    parent carrying multiple VLAN units in distinct zones would evaluate the
    wrong zone for every unit but the first. The three sites now mirror the
    filter (`poll_descriptor/filter.rs`) and CoS (`tx/cos_classify.rs`)
    call sites:
      - **#3021 — forwarding zone-pair:** both `from_zone` derivations in
        `poll_descriptor/mod.rs::poll_binding_process_descriptor` resolve
        the logical ingress ifindex before
        `zone_pair_ids_for_flow_with_override`, so a VLAN sub-interface is
        policed under its OWN ingress zone-pair.
      - **#3022 — screen / SYN-cookie:** `stage_screen_check` and
        `stage_screen_syn_cookie_ack_on_session_miss` resolve the logical
        ifindex before the `ifindex_to_zone_id` lookup, so the correct
        screen profile applies (a parent-zone miss would otherwise SKIP
        screening entirely, or apply the wrong profile).
      - **#3026 — generated ICMP error:** `icmp.rs` classifies the
        generated reply (CoS queue / DSCP rewrite / output filter) on the
        LOGICAL egress unit ifindex (`ingress_ident.ifindex`, the key for
        `forwarding.egress`), NOT the physical `target_ifindex` /
        `bind_ifindex`. `target_ifindex` (physical) is still used for the
        XSK transmit.
    Untagged ports resolve physical == logical, so all four sites are
    no-ops there (non-VLAN behavior preserved).
  - **NA validation (`#2368`, RFC 4861 §7.1.2 / RFC 4443):** before an
    NA learns a Target Link-Layer Address, `parse_ndp_neighbor_advert`
    enforces the §7.1.2 MUSTs — IPv6 Hop Limit == 255 (the off-link
    impersonation gate: a lower hop limit means a router forwarded the
    packet, so it did not originate on-link), ICMPv6 Code == 0, ICMP
    length >= 24, Target Address not multicast, and a valid ICMPv6
    checksum (computed over the IPv6 pseudo-header via the shared
    `frame::checksum16_*` accumulator). Any failure → `None` (no learn),
    so a spoofed/off-link NA cannot poison the cache.
  - **payload_len-bounded option walk (`#2368` B, #2361 class):** the
    NDP option walk (locating the TLLA) is bounded by the IPv6-declared
    packet end (`l3 + 40 + payload_len`, rejected if it overruns the
    frame), NOT the raw Ethernet frame length. A short NA whose declared
    payload covers only the fixed header cannot smuggle a forged TLLA in
    the L2 trailer/padding — trailing slack is never read as a
    link-layer address.
  - **NS scope:** there is NO Neighbor Solicitation learning path in the
    userspace dataplane (NS is never parsed or learned), so #2368 is
    NA-only; there is no sibling NS gap to close here.
  - **ARP fixed-header validation (`#2369`, RFC 826):** the sender MAC
    (`l3+8..14`) and sender IP (`l3+14..18`) sit at offsets that are only
    correct for Ethernet/IPv4 ARP. Before reading them, `classify_arp`
    now requires htype==1 (Ethernet), ptype==0x0800 (IPv4), hlen==6, and
    plen==4 (in addition to opcode==2 reply and a fully-present 28-byte
    body). A crafted opcode-2 ARP declaring a different hardware/protocol
    type or length would otherwise be read at the fixed Ethernet/IPv4
    offsets and the attacker-chosen bytes learned as a MAC->IP binding —
    an on-link neighbor-cache/kernel-table poisoning primitive. Any
    mismatch → `OtherArp` (recycled, never learned), the ARP sibling of
    the #2368 NA fail-closed discipline. Only opcode-2 replies are ever
    learned; ARP requests (opcode 1) classify `OtherArp` and never write
    the cache.
- `neighbor.rs` — netlink neighbor monitor (`neigh_monitor_thread`),
  startup dump (`initial_neighbor_dump` / `process_dump_batch`), the
  on-demand resolver glue, and `worker::pin_current_thread`. The monitor
  publishes `neighbor_generation` — the epoch counter the on-demand
  resolver snapshots for its guard, and whose value `1` is the
  **"initial baseline acquired" sentinel**.
  - **Generation-1 baseline invariant (`#2919`):** `neighbor_generation`
    is advanced to `1` ONLY when a full v4+v6 startup dump COMPLETES
    (`initial_neighbor_dump` → `Ok`). A failed dump (timeout /
    `WouldBlock` / `NLMSG_ERROR`) acquired no baseline and is NOT
    published as `1`; the monitor retries the full dump on a bounded
    backoff (`INITIAL_DUMP_RETRY_BACKOFF_MS`, `stop`-aware) until one
    pass succeeds. If every retry fails the generation stays `0`
    ("baseline incomplete"); the steady-state per-batch `fetch_add` and
    the ENOBUFS re-dump path then recover the population from `0` rather
    than from a bogus `1`. The publish/skip decision is the pure
    `dump_establishes_baseline` predicate (unit-tested fail-on-revert).
    The pre-#2919 bug stored `1` on BOTH the `Ok` and `Err` arms with no
    retry, so a failed initial dump looked like a completed empty
    baseline and quiet neighbors were stranded until an unrelated later
    event — an avoidable first-packet blackhole after startup / HA
    failover. The seq-0 absorb in `process_dump_batch` (`#2918`) is the
    sibling completeness fix on the success path and is preserved.
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
    The decision sizes off the IP-DECLARED L3 datagram length (IPv4
    `total_len` / IPv6 `40 + payload_len`, each clamped to the buffer) —
    the SAME length authority the PTB builders quote — NOT the raw AF_XDP
    buffer length, so ethernet padding / trailing bytes never mis-fire or
    mis-size a PTB (#2783); an unparseable/truncated IP header fails open
    to forward. When that declared length exceeds the egress MTU and the
    sender forbade fragmentation (IPv4 DF) or it is IPv6, it generates an
    ICMP
    Frag-Needed (v4 type 3 code 4, next-hop MTU per RFC 1191) / Packet
    Too Big (v6 type 2, MTU per RFC 4443) back out the ingress interface
    and drops the oversized original (`mtu_signalled` keeps
    `retained_source_frame` false → the finalizer recycles the ingress
    descriptor; a suppressed/unbuildable reply is the fail-closed silent
    drop). The reply is built inside the `target_binding` borrow and
    enqueued onto `ingress_binding` once that borrow ends.
    **Post-transform PMTUD (#2330):** the #2301 decision above compares the
    SOURCE frame against the egress MTU, which is correct ONLY for a
    size-preserving plain forward. For the size-CHANGING paths (NAT64,
    native GRE, WireGuard) the on-wire frame grows (encap) or its header
    shrinks/grows (NAT64), so a source-vs-egress comparison is wrong and
    #2301 skipped them entirely — leaving the inner source with NO PMTUD
    signal (a silent blackhole). #2330 derives the INNER-source MTU (the
    largest inner IP packet whose TRANSFORMED frame fits the
    egress/transport MTU) from the #2300/#2331 SSOT helpers
    (`post_transform_inner_mtu` → `native_gre_inner_mtu` for GRE,
    `wg::mss::wg_inner_mtu` for WireGuard, the v6↔v4 ±20 header delta for
    NAT64) and runs the SAME `forwarded_egress_mtu_decision` + builders
    against the inner `source_frame` (which IS the pre-encap / pre-translate
    inner packet, with `meta.addr_family` the inner family). The generated
    PTB carries the INNER MTU and routes through `classify_generated_reply`
    (#2328) at the finalizer, identically to the plain path. This CLOSES the
    PTB signal #2331 deferred: an oversized GRE/WG inner now yields a
    Frag-Needed/PTB instead of a silent `GRE_ENCAP_DF_OVERSIZE_DROPS` /
    `encap_mtu_drops` — and because `mtu_signalled` skips the build entirely,
    there is no double-drop/double-count with those encap guards (a non-DF
    IPv4 inner stays fragmentable → `Forward` → the #2331 drop guard remains
    the backstop). `mtu == 0` (no MTU resolvable / unknown tunnel kind)
    fails open to `Forward`.
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
  first octet; all-FF broadcast is a group address). #2367: the gate now
  also drops PTBs triggered by a datagram whose IP SOURCE is not a single
  unicast host (unspecified, loopback, multicast, or — for IPv4 —
  broadcast). The PTB is addressed to the trigger's source, so a forbidden
  source would emit spoofable ICMP backscatter; this is the L3-SOURCE half
  of RFC 1812 §4.3.2.7 / RFC 4443 §2.4(e). Both `ptb_reply_suppressed` and
  `can_generate_icmp_error_reply` now call the shared
  `source_is_invalid_for_icmp_error` predicate (`frame/inspect.rs`), so the
  PTB, reject, and Time-Exceeded paths apply ONE bad-source set (the
  reject gate's inlined source check was refactored to call it, closing
  the forkable per-error-type suppression contract). No new counter: a
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
  past an output `discard`. #2411: the gate now ALSO drops ICMP errors
  (reject, Time-Exceeded, and PTB) triggered by an IPv4 datagram destined
  to a *subnet-directed* broadcast — the all-ones host of a configured
  connected prefix, e.g. `10.0.1.255` for a connected `10.0.1.0/24`. RFC
  1812 §4.3.2.7 forbids originating an ICMP error to any broadcast,
  directed broadcasts included; but a directed broadcast is a plain
  unicast to the limited-broadcast (`255.255.255.255`) / multicast tests,
  so recognizing it needs the configured subnet MASK. The new shared
  `dest_is_directed_broadcast` predicate (`frame/inspect.rs`) reuses the
  forwarding state's connected-route table (`connected_v4`, the SAME rows
  the FIB lookup scans — no new infrastructure) and suppresses when the
  destination equals `network | !mask` of a connected prefix shorter than
  /31 (a /31 has no broadcast per RFC 3021 and a /32's all-ones host is
  the host itself, so both are skipped to avoid mis-suppressing a
  legitimate unicast). `can_generate_icmp_error_reply` and
  `ptb_reply_suppressed` both take `&ForwardingState` and call it (v4-only
  — IPv6 has no broadcast), so the reject, Time-Exceeded, and PTB paths
  apply ONE directed-broadcast gate. The lookup is a COLD-path scan: it
  runs only when an ICMP error is about to be generated, never on the
  per-packet fast path. No new counter — a suppressed error folds into
  the existing fail-closed silent drop.
  #2487: the SOURCE-side sibling of #2411. A locally generated ICMP error
  is addressed TO the trigger packet's source, so a *subnet-directed
  broadcast* SOURCE (the all-ones host of a connected prefix, e.g.
  `10.0.1.255` for `10.0.1.0/24`) produces an error emitted to that
  directed broadcast — delivered to every host on the segment
  (Smurf-style amplification / backscatter). The limited-broadcast test
  in `source_is_invalid_for_icmp_error` (`is_broadcast()`) only catches
  `255.255.255.255`; a subnet-directed broadcast is a plain unicast to it
  and needs the configured subnet MASK. The new shared
  `src_is_directed_broadcast` predicate (`frame/inspect.rs`) reuses the
  SAME `connected_v4` scan (extracted into the shared
  `v4_addr_is_directed_broadcast` helper that `dest_is_directed_broadcast`
  also now calls) and the SAME `/31`/`/32` prefix-length guards. The IPv4
  arms of `can_generate_icmp_error_reply` and `ptb_reply_suppressed` call
  it alongside the existing source check (v4-only — IPv6 has no
  broadcast), so the reject, Time-Exceeded, and PTB paths apply ONE
  bad-source set covering both the limited and directed broadcast. Same
  cold-path scan, no new counter, fail-closed silent drop.
  #2472: AFTER the RFC suppression + output-classification gates, all three
  locally-generated error reasons (Time Exceeded, PTB/Frag-Needed, and
  policy/filter `reject`) now also pass through a per-reason token-bucket
  RATE LIMITER (`icmp_ratelimit.rs`). Without it, a flood of TTL-1 packets,
  oversized-DF packets, or rejected flows (or a routing loop) made the box
  emit one generated error PER trigger packet, unbounded — a CPU/TX
  amplification sink and a reflection vector (the errors are addressed to the
  trigger's source, which an attacker can spoof). The bucket is
  GLOBAL-PER-REASON (no per-source / per-destination map → no
  attacker-driven state growth), modelled on Linux's `net.ipv4.icmp_msgs_per_sec`
  (a global per-host burst). Each reason has its OWN bucket so a TTL-exceeded
  flood cannot starve PTB or reject (per-reason isolation). Defaults:
  `DEFAULT_RATE_PER_SEC = 1000` tokens/s refill + `DEFAULT_BURST = 1000`
  capacity, PER reason (compile-time; a rate of 0 disables the limiter). The
  check is a single CAS loop over ONE atomic word — a GCRA (Generic Cell Rate
  Algorithm) theoretical-arrival-time, the same single-TAT pattern used by
  `event_stream/producer.rs` — on the cold generated-error path only, never per
  forwarded packet, no allocation. #2955: the limiter previously split its state
  into TWO atomics (a millitoken count + a last-refill timestamp) and CAS-
  committed only the token count, publishing the timestamp as a SEPARATE relaxed
  store. Under multi-worker contention two workers could read the new (lower)
  token count with the stale OLD timestamp and credit the same refill interval
  twice (double-credit), or both observe the first-use (`last_ns == 0`) branch
  and each refill to full burst — OVER-ADMITTING generated errors past the
  configured rate (a DoS-boundary weakening) and corrupting the
  `*_rate_limited_total` counters. Collapsing the state into the single GCRA word
  makes refill and consume commit together in ONE compare-exchange, so the
  admitted rate is hard-capped regardless of interleaving. On bucket-empty the generated reply is DROPPED (the TTL/reject
  paths fail-closed to the silent drop they already perform; the PTB path
  still drops the oversized original via `mtu_signalled`, so it never falls
  through to forward the MTU-violating frame) and a per-reason observable
  counter is bumped — surfaced via the coordinator status as
  `xpf_userspace_time_exceeded_rate_limited_total`,
  `xpf_userspace_packet_too_big_rate_limited_total`, and
  `xpf_userspace_reject_rate_limited_total`. The pre-existing SYN-cookie
  TX-frame budget gate on the reject path STAYS: it is queue protection (it
  keeps the reply ring from starving transit TX), a separate concern from the
  per-reason rate cap. Wired at the three generation sites:
  `icmp::build_local_time_exceeded_request`, the PTB build in
  `tx/dispatch/mod.rs`, and `poll_descriptor::reject_reply::enqueue_reject_reply`
  (covering both policy and filter reject — a single emit path).
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

## Shared-session map poison policy (#2402)

The HA promotion/demotion path reads and mutates three shared-session
maps (`Mutex<FastMap<SessionKey, SyncedSessionEntry>>` — synced, NAT, and
forward-wire) plus their owner-RG indexes. A worker panic while holding
one of these mutexes (contained by the #925 supervisor) poisons it, and
the map still holds every committed insert.

The old access patterns SWALLOWED that poison and lost the data:

- `prewarm_reverse_synced_sessions_for_owner_rgs` used
  `shared_sessions.lock().map(|s| { … }).unwrap_or_default()`. On a
  poisoned lock the `.map` closure was skipped and `unwrap_or_default()`
  substituted EMPTY `(forward_entries, reverse_entries)` — so RG
  activation proceeded as if there were **no sessions to promote** and
  silently dropped every active synced session at the exact moment of
  failover (the #2402 bug).
- `demote_shared_owner_rgs`, `publish_shared_session`,
  `remove_shared_session`, the `lookup_shared_*` helpers,
  `republish_bpf_session_entries_for_owner_rgs`, and the owner-RG index
  maintenance helpers used `if let Ok(..)` / `.lock().ok()` /
  `match .lock() { Err(_) => return }`, each of which silently SKIPPED its
  work (a missed demotion, a dropped publish/remove, a spurious lookup
  miss) on poison.

`shared_ops::lock_shared_recover` replaces all of them with poison
RECOVERY — `into_inner()` to keep the committed map, `clear_poison()` to
restore the fast path, and a bump of `SHARED_SESSION_POISON_RECOVERIES`
plus a sparse journald line so operators see the underlying worker panic.
This mirrors the worker-command-queue policy above (`worker_queue.rs`,
#1807): a contained panic must never void failover — promotion/demotion
proceeds with the existing session data. The unrelated `mode`-mutex
status reads in `state_writer.rs` / `slowpath.rs` keep
`.lock().map(..).unwrap_or_default()` deliberately (a momentary
default-mode status read is harmless and not on the session path).

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
