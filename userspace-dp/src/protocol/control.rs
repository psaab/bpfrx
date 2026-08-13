//! Control socket request/response wire shapes, `ProcessStatus`
//! (the per-tick status aggregate), and session-sync wire shapes.
//! Deepest module in the `protocol/` DAG: depends on every leaf
//! plus `snapshot` because `ProcessStatus` and `ControlRequest`
//! aggregate them.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::binding::{
    BindingCountersSnapshot, BindingStatus, ExceptionStatus, HAGroupStatus, QueueStatus,
    SessionDeltaInfo, WorkerRuntimeStatus,
};
use super::cos::{CoSActiveFlowCountStatus, CoSInterfaceStatus};
use super::nat::{NatRuleCounterStatus, SourceNatPoolStatus};
use super::resolution::{FlowWorkerStatus, PacketResolution};
use super::security::{
    FirewallFilterTermCounterStatus, PolicyRuleCounterStatus, ThreeColorPolicerStatus,
};
use super::snapshot::{ConfigSnapshot, FabricSnapshot, NeighborSnapshot, UserspaceCapabilities};

/// The config-snapshot wire contract version, mirrored on the Go side by
/// `userspace.ProtocolVersion` (pkg/dataplane/userspace/protocol.go). The two
/// MUST be bumped in lockstep: both `apply_snapshot` and `bump_fib_generation`
/// gate on EXACT equality, so a peer at a different version refuses the
/// snapshot outright instead of decoding it under the wrong contract.
///
/// v4 (#5488): a scoped GLOBAL policy carries its zone SCOPE as a zone SET in
/// the plural `match_from_zones`/`match_to_zones` fields, and those fields are
/// AUTHORITATIVE (`effective_match_zones` prefers them). The singular
/// `match_from_zone`/`match_to_zone` fields carry only the FIRST element.
///
/// #4626 added the plural fields as purely ADDITIVE JSON without bumping this
/// constant, which made the version handshake lie: a pre-#4626 helper
/// advertising the same version 3 ignores fields it does not know and reads
/// ONLY the singular field, so a global `deny` scoped `[dmz trust] -> untrust`
/// silently NARROWS to `dmz -> untrust` — a rolling-upgrade fail-OPEN for the
/// zones dropped from the scope. A compatibility extension that changes
/// deny/reject COVERAGE must not be silently ignorable under an unchanged
/// protocol version.
pub(crate) const CONFIG_SNAPSHOT_PROTOCOL_VERSION: i32 = 4;
pub(crate) const INJECT_PACKET_TUPLE_PROTOCOL_VERSION: i32 = 1;

/// #3651: one per-zone traffic-volume row inside the `ProcessStatus`-level
/// `zone_traffic_counters` sparse block. `zone_id` is the stable name-hash
/// zone id (`StableZoneID`, matching `ZoneSnapshot.id`); ingress totals count
/// packets/bytes that entered the firewall through an interface in the zone,
/// egress totals count packets/bytes that left through one. Totals are
/// cumulative since helper start (or the last `clear_zone_counters` IPC). The
/// Go mirror is `ZoneTrafficCounterStatus` with json tags
/// `zone_id`/`ingress_packets`/`ingress_bytes`/`egress_packets`/`egress_bytes`.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct ZoneTrafficCounterStatus {
    #[serde(rename = "zone_id", default)]
    pub zone_id: u16,
    #[serde(rename = "ingress_packets", default)]
    pub ingress_packets: u64,
    #[serde(rename = "ingress_bytes", default)]
    pub ingress_bytes: u64,
    #[serde(rename = "egress_packets", default)]
    pub egress_packets: u64,
    #[serde(rename = "egress_bytes", default)]
    pub egress_bytes: u64,
}

/// #3651: one per-zone flood-EVENT row inside the `ProcessStatus`-level
/// `zone_flood_counters` sparse block — the sibling of
/// [`ZoneTrafficCounterStatus`] for the other dead per-zone counter family.
/// `zone_id` is the stable name-hash zone id (`StableZoneID`, matching
/// `ZoneSnapshot.id`); the three counts are cumulative screen DROPS attributed
/// to that zone for the `syn-flood`, `icmp-flood`, and `udp-flood` checks,
/// since helper start (or the last `clear_flood_counters` IPC). The Go mirror
/// is `ZoneFloodCounterStatus` with json tags
/// `zone_id`/`syn_flood_events`/`icmp_flood_events`/`udp_flood_events`, which
/// `syncBPFCountersLocked` maps onto `dataplane.FloodState`
/// `SynCount`/`ICMPCount`/`UDPCount`.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub(crate) struct ZoneFloodCounterStatus {
    #[serde(rename = "zone_id", default)]
    pub zone_id: u16,
    #[serde(rename = "syn_flood_events", default)]
    pub syn_flood_events: u64,
    #[serde(rename = "icmp_flood_events", default)]
    pub icmp_flood_events: u64,
    #[serde(rename = "udp_flood_events", default)]
    pub udp_flood_events: u64,
}

/// Maximum accepted size, in bytes, of a single newline-delimited
/// control-socket request body before it is decoded (#2523).
///
/// The control socket reads one JSON request per connection via a
/// bounded `read_until`. Without a cap, a malformed or compromised local
/// caller can stream a very large unterminated line and force the helper
/// to grow its read buffer unbounded (bounded in time only by the 5 s
/// read timeout, not in allocation). The accept loop reads the whole body
/// into memory before any schema validation can run, so the cap must be
/// enforced at the read, not at decode.
///
/// Sizing (#2744): the largest legitimate request is `apply_snapshot`,
/// which carries the entire compiled config (every zone, policy,
/// address-book entry, NAT rule, filter, route, etc.). A hand-authored
/// production config serializes to a few MB of JSON, but the DOMINANT
/// scaling dimension is NOT policy count — it is dynamic-feed-backed
/// address books: `AddressBookSnapshot.prefixes_v4/v6` carry feed
/// prefixes inline as CIDR text (see `buildAddressBookTableWithFeeds`,
/// `pkg/dataplane/userspace/policies.go`), and feeds are bounded only by
/// a per-line scanner cap, not a total-entry cap.
///
/// The original #2523 ceiling was 16 MiB, sized off the policy/NAT/route
/// dimension. A large threat-intel feed (hundreds of thousands of CIDRs;
/// an IPv6 CIDR serializes to ~45 B of JSON each, so ~500K prefixes ≈
/// 20+ MiB) can push a *legitimate* `apply_snapshot` past 16 MiB and be
/// rejected at the control socket — fail-closed, but it silently drops a
/// committed config on the floor. #2744 raises the ceiling to 64 MiB,
/// sized to the feed dimension: 64 MiB / ~45 B per IPv6 CIDR ≈ 1.4M
/// prefixes, comfortably above realistic large-feed deployments while
/// still bounding a single request's read allocation to a fixed ceiling.
/// A request larger than this is rejected before allocating its body,
/// keeping the daemon alive (fail-closed: stale config retained, one log
/// line, no crash).
///
/// LOCKSTEP: this MUST equal the Go sender's pre-flight ceiling
/// `MaxControlRequestBytes` in `pkg/dataplane/userspace/process.go`. A
/// sender that emits a request larger than the receiver's cap still gets
/// rejected at the read, so the two caps must move together. The Go side
/// pins the relationship in `TestControlRequestCapLockstepWithRust`.
pub(crate) const MAX_CONTROL_REQUEST_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ControlRequest {
    #[serde(rename = "type")]
    pub request_type: String,
    #[serde(rename = "suppress_status", default)]
    pub suppress_status: bool,
    #[serde(default)]
    pub snapshot: Option<ConfigSnapshot>,
    #[serde(default)]
    pub forwarding: Option<ForwardingControlRequest>,
    #[serde(rename = "ha_state", default)]
    pub ha_state: Option<HAStateUpdateRequest>,
    #[serde(default)]
    pub queue: Option<QueueControlRequest>,
    #[serde(default)]
    pub binding: Option<BindingControlRequest>,
    #[serde(default)]
    pub packet: Option<InjectPacketRequest>,
    #[serde(rename = "session_sync", default)]
    pub session_sync: Option<SessionSyncRequest>,
    #[serde(rename = "session_deltas", default)]
    pub session_deltas: Option<SessionDeltaDrainRequest>,
    #[serde(rename = "session_export", default)]
    pub session_export: Option<SessionExportRequest>,
    #[serde(default)]
    pub neighbors: Option<Vec<NeighborSnapshot>>,
    #[serde(rename = "neighbor_generation", default)]
    pub neighbor_generation: u64,
    #[serde(rename = "neighbor_replace", default)]
    pub neighbor_replace: bool,
    #[serde(default)]
    pub fabrics: Option<Vec<FabricSnapshot>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ProcessStatus {
    pub pid: i32,
    #[serde(rename = "config_snapshot_protocol_version", default)]
    pub config_snapshot_protocol_version: i32,
    #[serde(rename = "inject_packet_tuple_protocol_version", default)]
    pub inject_packet_tuple_protocol_version: i32,
    #[serde(rename = "started_at")]
    pub started_at: DateTime<Utc>,
    #[serde(rename = "control_socket")]
    pub control_socket: String,
    #[serde(rename = "state_file")]
    pub state_file: String,
    pub workers: usize,
    #[serde(rename = "ring_entries")]
    pub ring_entries: usize,
    #[serde(rename = "helper_mode")]
    pub helper_mode: String,
    #[serde(rename = "io_uring_planned")]
    pub io_uring_planned: bool,
    #[serde(rename = "io_uring_active", default)]
    pub io_uring_active: bool,
    #[serde(rename = "io_uring_mode", default)]
    pub io_uring_mode: String,
    #[serde(rename = "io_uring_last_error", default)]
    pub io_uring_last_error: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(rename = "forwarding_armed", default)]
    pub forwarding_armed: bool,
    #[serde(default)]
    pub capabilities: UserspaceCapabilities,
    #[serde(rename = "last_snapshot_generation")]
    pub last_snapshot_generation: u64,
    #[serde(rename = "last_fib_generation", default)]
    pub last_fib_generation: u32,
    #[serde(rename = "last_snapshot_at", skip_serializing_if = "Option::is_none")]
    pub last_snapshot_at: Option<DateTime<Utc>>,
    #[serde(rename = "interface_addresses", default)]
    pub interface_addresses: usize,
    #[serde(rename = "neighbor_entries", default)]
    pub neighbor_entries: usize,
    /// Total entries installed in the Rust-owned worker session tables.
    /// Additive for mixed-version compatibility: older helpers omit it
    /// and Go treats zero max_sessions as "no denominator available".
    #[serde(rename = "session_table_entries", default)]
    pub session_table_entries: usize,
    /// Aggregate capacity of the Rust-owned worker session tables.
    #[serde(rename = "max_sessions", default)]
    pub max_sessions: usize,
    /// #1760: aggregate NAT reverse-key displacement events summed across
    /// the per-worker session tables — the latent 1:N collision (#1758)
    /// made observable. A near-precise upper bound on live collisions
    /// (counts displacement *events*, not distinct flow-pairs). Additive
    /// for mixed-version compatibility: older helpers omit it (defaults to
    /// 0). A nonzero value triggers the structural-fix research; this
    /// counter does NOT resolve #1760.
    #[serde(rename = "nat_reverse_key_collisions", default)]
    pub nat_reverse_key_collisions: u64,
    /// #1861: aggregate at-cap install refusals summed across the
    /// per-worker session tables (`SessionTable::create_drops` — was
    /// write-only/invisible before #1861). Additive: older helpers omit
    /// it (defaults to 0).
    #[serde(rename = "session_create_drops", default)]
    pub session_create_drops: u64,
    /// #1861: aggregate pair-admission preflight refusals (one per
    /// refused flow) — the new-flow transaction boundary dropping a
    /// trigger packet at/near max_sessions. Additive.
    #[serde(rename = "session_install_admission_refused", default)]
    pub session_install_admission_refused: u64,
    /// #1861: aggregate post-preflight partial-install residuals.
    /// Expected 0 forever; nonzero means the preflight/install pairing
    /// has a bug. Additive.
    #[serde(rename = "session_install_partial", default)]
    pub session_install_partial: u64,
    /// Aggregate per-binding flow-cache capacity across helper-published
    /// binding status rows. Zero means unavailable, not full.
    #[serde(rename = "flow_cache_capacity", default)]
    pub flow_cache_capacity: usize,
    /// Hard capacity for the dynamic neighbor cache. The current
    /// sharded map is growable, so zero intentionally suppresses
    /// utilization rows until Rust owns a real bounded denominator.
    #[serde(rename = "neighbor_cache_capacity", default)]
    pub neighbor_cache_capacity: usize,
    #[serde(rename = "neighbor_generation", default)]
    pub neighbor_generation: u64,
    /// #6034: ACK of the highest authoritative manager-neighbor REPLACE
    /// generation the helper has applied. Distinct from
    /// `neighbor_generation` (the dynamic ARP/NDP resolver epoch): this
    /// echoes the `neighbor_generation` field the Go manager stamps on an
    /// `update_neighbors` replace so the manager can confirm the clear /
    /// replace landed and retain retry debt otherwise. Additive / defaulted:
    /// an older helper omits it (Go decodes 0 → treats as "no ACK support,
    /// assume applied", preserving pre-#6034 behavior).
    #[serde(rename = "manager_neighbor_generation", default)]
    pub manager_neighbor_generation: u64,
    #[serde(rename = "route_entries", default)]
    pub route_entries: usize,
    #[serde(rename = "worker_heartbeats", default)]
    pub worker_heartbeats: Vec<DateTime<Utc>>,
    /// #869: per-worker busy/idle runtime telemetry.  Empty on
    /// dataplanes that don't publish.  Additive / defaulted for
    /// backward compatibility with older daemon builds.
    #[serde(rename = "worker_runtime", default)]
    pub worker_runtime: Vec<WorkerRuntimeStatus>,
    // #710: cluster-wide aggregate of cross-worker CoS redirects that
    // could not locate a binding for their target egress on the landing
    // worker. Summed across all bindings in `refresh_status` — the
    // per-binding accounting is a mechanical choice (the increment
    // always lands on the landing worker's first binding), so the
    // per-binding view would be misleading as triage signal; the total
    // is the operator-facing number.
    #[serde(rename = "cos_no_owner_binding_drops_total", default)]
    pub cos_no_owner_binding_drops_total: u64,
    /// #1636 option C: proactive-neighbor-warm telemetry. `warm_drops`
    /// counts warm requests dropped because the bounded warmer queue was
    /// full (transient saturation under route churn); `warm_disconnected`
    /// counts requests dropped because the warmer worker thread died
    /// (fatal — warming disabled until restart). Both are the only
    /// operator-visible signal in production builds (debug-log off) and
    /// are surfaced as Prometheus counters by the Go collector. Additive
    /// / defaulted for backward compatibility with older daemons.
    #[serde(rename = "neighbor_warm_drops_total", default)]
    pub neighbor_warm_drops_total: u64,
    #[serde(rename = "neighbor_warm_disconnected_total", default)]
    pub neighbor_warm_disconnected_total: u64,
    /// #1782 cold-start capture instrumentation. Per-binding-summed
    /// count of neg-neigh-cache fast-fails (H1 amplifier signal) and of
    /// `pending_neigh` sibling drops where the `(egress_ifindex,
    /// next_hop)` key was already pending (H5 sibling-drop signal). Both
    /// are surfaced as Prometheus counters by the Go collector. Additive
    /// / defaulted for backward compatibility with older daemons.
    #[serde(rename = "neg_neigh_fast_fail_total", default)]
    pub neg_neigh_fast_fail_total: u64,
    #[serde(rename = "pending_neigh_duplicate_drops_total", default)]
    pub pending_neigh_duplicate_drops_total: u64,
    /// #1902: GRE-decapped MissingNeighbor packets refused
    /// `pending_neigh` admission (buffering the outer UMEM frame with
    /// the post-decap inner meta would retry-TX a mis-rewritten outer
    /// packet). Additive / defaulted for backward compatibility.
    #[serde(rename = "pending_neigh_decap_drops_total", default)]
    pub pending_neigh_decap_drops_total: u64,
    /// #2375: MissingNeighbor packets for a NEW distinct
    /// `(egress_ifindex, next_hop)` refused because `pending_neigh` is at
    /// `MAX_PENDING_NEIGH` distinct hops (distinct-hop neighbor
    /// exhaustion — the scan/upstream-outage failure mode). Kept distinct
    /// from `pending_neigh_duplicate_drops_total` (the key was already
    /// pending — normal cold-start coalescing). Additive / defaulted for
    /// backward compatibility with older daemons.
    #[serde(rename = "pending_neigh_capacity_drops_total", default)]
    pub pending_neigh_capacity_drops_total: u64,
    /// #5673: cumulative data-path neighbor LEARNS refused because the
    /// dynamic-neighbor map's target shard was at
    /// `MAX_DYNAMIC_NEIGHBORS_PER_SHARD`. Source-address learning runs on RX
    /// BEFORE screen/policy admission, so an attacker on an untrusted segment
    /// can otherwise inflate the shared map with one entry per spoofed source
    /// (a pre-policy CPU/memory DoS). A rising value is the always-on signal
    /// that the aggregate cap is bounding such a flood. Additive / defaulted
    /// for backward compatibility with older daemons.
    #[serde(rename = "dynamic_neighbor_learn_cap_drops_total", default)]
    pub dynamic_neighbor_learn_cap_drops_total: u64,
    /// #1789: total failed USERSPACE_SESSIONS BPF-map publishes
    /// (per-binding worker-poll sites summed with the shared no-binding
    /// sites: HA upsert, session-glue worker publish, post-reconcile
    /// replay, activation/reverse prewarm). Always-on cause-side signal
    /// for rising XDP-shim NO_SESSION degraded-path fallbacks (session
    /// map at capacity, stale fd after reconcile). Surfaced as the
    /// Prometheus counter `xpf_userspace_session_publish_errors_total`.
    /// Additive / defaulted for backward compatibility.
    #[serde(rename = "session_publish_errors_total", default)]
    pub session_publish_errors_total: u64,
    /// #4800: cross-worker contention accounting for the per-new-flow
    /// install path, so a connection-rate run can name the saturated
    /// synchronization point instead of inferring one from a flattened
    /// new-flows/sec curve.
    ///
    /// Read as pairs: `..._lock_contended_total / ..._lock_acquisitions_total`
    /// is the publish leg's blocked fraction, and
    /// `session_replication_lock_contended_total / session_replication_enqueued_total`
    /// the replication leg's. `session_replication_enqueued_total /
    /// session_replication_upserts_total` recovers the N-way sibling
    /// fan-out. `session_replication_queue_depth_max` is a monotonic
    /// high-water gauge, not a counter — do not `rate()` it.
    ///
    /// The NAT-allocator leg is per pool and rides `source_nat_pools`
    /// (`live_lock_acquisitions_total` / `live_lock_contended_total`)
    /// rather than these process-global fields. All additive / defaulted
    /// for backward compatibility.
    #[serde(rename = "shared_session_publishes_total", default)]
    pub shared_session_publishes_total: u64,
    #[serde(rename = "shared_session_publish_lock_acquisitions_total", default)]
    pub shared_session_publish_lock_acquisitions_total: u64,
    #[serde(rename = "shared_session_publish_lock_contended_total", default)]
    pub shared_session_publish_lock_contended_total: u64,
    #[serde(rename = "session_replication_upserts_total", default)]
    pub session_replication_upserts_total: u64,
    #[serde(rename = "session_replication_enqueued_total", default)]
    pub session_replication_enqueued_total: u64,
    #[serde(rename = "session_replication_lock_contended_total", default)]
    pub session_replication_lock_contended_total: u64,
    /// #4800: sum of the per-call deepest sibling-queue depth. Divided by
    /// `session_replication_upserts_total` over the same window this is the
    /// MEAN worst-sibling depth per replicated flow — the differenceable
    /// backlog statistic. The `_max` below is a process-lifetime high-water
    /// that CANNOT be differenced (it never falls, so a zero delta is
    /// ambiguous and the absolute value stays elevated forever after one
    /// spike) and is therefore operator context only, never a verdict input.
    #[serde(rename = "session_replication_queue_depth_sum", default)]
    pub session_replication_queue_depth_sum: u64,
    #[serde(rename = "session_replication_queue_depth_max", default)]
    pub session_replication_queue_depth_max: u64,
    /// #2244: total failed `dnat_table` reverse-SNAT BPF-map publishes
    /// summed across worker bindings. The `dnat_table` is the reverse
    /// lookup the embedded-ICMP NAT path consults to map an inbound ICMP
    /// error (PMTUD Packet Too Big / Time Exceeded / traceroute) back to
    /// the original pre-NAT source; a failed publish silently omits the
    /// record so the error is dropped or mis-delivered. Always-on
    /// cause-side signal for `dnat_table` map-capacity pressure. Surfaced
    /// as the Prometheus counter `xpf_userspace_dnat_publish_errors_total`.
    /// Additive / defaulted for backward compatibility.
    #[serde(rename = "dnat_publish_errors_total", default)]
    pub dnat_publish_errors_total: u64,
    /// #5674: peer-synced session imports rejected by the coordinator's
    /// aggregate admission bound (`upsert_synced_session`). Locally-created
    /// sessions are capped per worker at `max_sessions`; peer-synced imports
    /// were previously uncapped and fanned out to every worker, so a peer under
    /// session-table pressure (or a compromised peer) could drive this node
    /// past its own aggregate session ceiling and multiply that state across
    /// all workers. A rising value means a peer exceeded this appliance's own
    /// ceiling — stated in ENTRIES as `2 * worker_count * max_sessions` (#6413),
    /// matching `synced_import_cap`, not the LOGICAL `worker_count *
    /// max_sessions`. Each admitted forward publishes TWO keys (the forward and
    /// its synthesized reverse companion), so N logical sessions arrive as 2N
    /// entries and EXACTLY fit the cap; it never trips on a legitimate
    /// symmetric-pair failover. Surfaced as the Prometheus counter
    /// `xpf_userspace_synced_import_cap_drops_total`. Additive / defaulted for
    /// backward compatibility.
    #[serde(rename = "synced_import_cap_drops_total", default)]
    pub synced_import_cap_drops_total: u64,
    /// #1760 W3': shared-map NAT reverse-key displacement events — a
    /// `publish_shared_session` insert into `shared_nat_sessions`
    /// displaced a DIFFERENT forward session's entry at the same reverse
    /// key (two live forward NAT sessions mapping onto one reply tuple —
    /// the #1758/#1760 latent 1:N collision). The shared map is the
    /// single choke point all transit forward NAT sessions pass through,
    /// including `MissingNeighborSeed` installs the per-worker
    /// `nat_reverse_key_collisions` counter cannot see. Event count, not
    /// a pair census. Surfaced as the Prometheus counter
    /// `xpf_userspace_session_nat_reverse_key_shared_displacements_total`.
    /// Additive / defaulted for backward compatibility.
    #[serde(rename = "nat_reverse_key_shared_displacements_total", default)]
    pub nat_reverse_key_shared_displacements_total: u64,
    /// #1807: total worker-command-queue poison recoveries (a thread
    /// panicked while holding a `Mutex<VecDeque<WorkerCommand>>`; the
    /// committed queue was recovered via into_inner and the poison
    /// cleared — uniform policy in afxdp/worker_queue.rs, extends
    /// #1790). Nonzero means a worker panic happened and the command
    /// queues kept flowing instead of going permanently deaf. Surfaced
    /// as the Prometheus counter
    /// `xpf_userspace_worker_command_queue_poison_recoveries_total`.
    /// Additive / defaulted for backward compatibility.
    #[serde(rename = "worker_command_queue_poison_recoveries", default)]
    pub worker_command_queue_poison_recoveries: u64,
    /// #2315: GRE-decap frames dropped by the RFC 6040 §4.2 decap-side
    /// ECN combine because the outer header carried a CE mark over an
    /// inner packet that was Not-ECT (the illegal combination — a
    /// congested router CE-marked a packet whose endpoints never
    /// negotiated ECN). RFC 6040 mandates a drop here rather than
    /// silently clearing the bogus CE. Surfaced as the Prometheus
    /// counter `xpf_userspace_gre_decap_ecn_illegal_drops_total`;
    /// nonzero flags a misbehaving tunnel ingress on a congested path.
    /// Additive / defaulted for backward compatibility.
    #[serde(rename = "gre_decap_ecn_illegal_drops_total", default)]
    pub gre_decap_ecn_illegal_drops_total: u64,
    /// #2317: WireGuard-decap inner packets dropped by the SAME RFC 6040
    /// §4.2 decap-side ECN combine, for the WG path. The WG decap site
    /// captures the outer ECN out-of-band via `recvmsg` +
    /// `IP_RECVTOS`/`IPV6_RECVTCLASS` (the kernel UDP socket strips the
    /// outer IP header before userspace) and feeds it into the same
    /// combine. Surfaced as the Prometheus counter
    /// `xpf_userspace_wg_decap_ecn_illegal_drops_total`; nonzero flags a
    /// misbehaving WG ingress on a congested path. Additive / defaulted
    /// for backward compatibility.
    #[serde(rename = "wg_decap_ecn_illegal_drops_total", default)]
    pub wg_decap_ecn_illegal_drops_total: u64,
    /// #2331: native-GRE encap frames DROPPED because the fully built
    /// outer datagram (outer IP + GRE[+key] + inner) exceeded the
    /// resolved transport/egress MTU while the IPv4 outer carries DF=1
    /// (the only outer the native encap builder emits). A DF-set
    /// oversized outer cannot be fragmented downstream and would
    /// silently blackhole every inner flow with no PMTUD signal — so the
    /// builder refuses to emit it. Surfaced as the Prometheus counter
    /// `xpf_userspace_gre_encap_df_oversize_drops_total`; nonzero flags
    /// inner flows whose encapped size exceeds the tunnel path MTU.
    /// PMTUD/PTB signalling is deferred to #2330. Additive / defaulted
    /// for backward compatibility.
    #[serde(rename = "gre_encap_df_oversize_drops_total", default)]
    pub gre_encap_df_oversize_drops_total: u64,
    /// #2782: native-GRE decap frames DROPPED because the Checksum-Present
    /// (C) bit was set but the GRE checksum did not verify (or the header
    /// was truncated past the 4-byte Checksum+Reserved1 field). Per RFC
    /// 2784 §2.1 + RFC 2890 a checksummed peer (e.g. a vSRX with GRE
    /// checksum enabled) is now decapped after skipping+validating the
    /// checksum field instead of being silently blackholed; a frame the
    /// path corrupted is dropped HERE with this specific counter so the
    /// drop is observable. Surfaced as the Prometheus counter
    /// `xpf_userspace_gre_decap_checksum_invalid_drops_total`; nonzero
    /// flags a checksummed GRE peer delivering corrupt frames or a
    /// truncated GRE header. Additive / defaulted for backward
    /// compatibility.
    #[serde(rename = "gre_decap_checksum_invalid_drops_total", default)]
    pub gre_decap_checksum_invalid_drops_total: u64,
    /// #2472: locally-generated ICMP Time Exceeded / PTB / `reject` replies
    /// dropped because the per-reason token bucket was empty. Each reason has
    /// an independent global-per-reason bucket (Linux `icmp_msgs_per_sec`
    /// model, default 1000/s + 1000 burst) so an error-amplification /
    /// reflection flood (low-TTL stream, oversized-DF flood, rejected-flow
    /// flood, or a routing loop) cannot drive unbounded generated-error
    /// emission. Surfaced as the Prometheus counters
    /// `xpf_userspace_time_exceeded_rate_limited_total`,
    /// `xpf_userspace_packet_too_big_rate_limited_total`, and
    /// `xpf_userspace_reject_rate_limited_total`. Additive / defaulted for
    /// backward compatibility.
    #[serde(rename = "time_exceeded_rate_limited_total", default)]
    pub time_exceeded_rate_limited_total: u64,
    #[serde(rename = "packet_too_big_rate_limited_total", default)]
    pub packet_too_big_rate_limited_total: u64,
    #[serde(rename = "reject_rate_limited_total", default)]
    pub reject_rate_limited_total: u64,
    /// #1782 cold-start capture instrumentation. Debug dump of every key
    /// present in the userspace `dynamic_neighbors` mirror, rendered as
    /// `"ifindex ip"` strings. The capture harness greps this at the
    /// pre-connect t0' sample to confirm the data-path next-hop is ABSENT
    /// (the H2 fingerprint). Empty (and omitted) on dataplanes that don't
    /// publish, when the mirror is empty, OR — by default — because the dump
    /// is gated behind the `XPF_DEBUG_NEIGHBOR_KEYS` env var (off unless the
    /// helper is launched with it set for a capture). An empty field
    /// therefore does NOT imply the mirror is empty.
    #[serde(
        rename = "dynamic_neighbor_keys",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub dynamic_neighbor_keys: Vec<String>,
    /// #1769: on-demand neighbor-resolver telemetry. The resolver runs
    /// when a `MissingNeighbor` negative-cache fast-fail nudges a wedged
    /// dst: it issues a single-key RTM_GETNEIGH and either caches a
    /// confirmed lladdr (epoch-guarded) or probes to force kernel
    /// revalidation on a stale one. These are the operator-visible signal
    /// for the #1769 stuck-state (queue depth is a gauge; the rest are
    /// monotonic counters). Additive / defaulted for backward compat.
    #[serde(rename = "neighbor_resolver_queue_depth", default)]
    pub neighbor_resolver_queue_depth: u64,
    #[serde(rename = "neighbor_resolver_enqueue_drops_total", default)]
    pub neighbor_resolver_enqueue_drops_total: u64,
    #[serde(rename = "neighbor_resolver_disconnected_total", default)]
    pub neighbor_resolver_disconnected_total: u64,
    #[serde(rename = "neighbor_resolver_get_attempts_total", default)]
    pub neighbor_resolver_get_attempts_total: u64,
    #[serde(rename = "neighbor_resolver_get_resolved_total", default)]
    pub neighbor_resolver_get_resolved_total: u64,
    #[serde(rename = "neighbor_resolver_probe_on_stale_total", default)]
    pub neighbor_resolver_probe_on_stale_total: u64,
    #[serde(rename = "neighbor_resolver_get_failures_total", default)]
    pub neighbor_resolver_get_failures_total: u64,
    #[serde(rename = "neighbor_resolver_epoch_rejects_total", default)]
    pub neighbor_resolver_epoch_rejects_total: u64,
    /// #1772: neighbor/ARP resolution LATENCY telemetry. Complements the
    /// #1769 count-only resolver telemetry above with TIMING so the
    /// operator's intermittent slow-new-connection symptom is visible.
    /// Histogram buckets are NON-cumulative per-bucket sample counts on a
    /// 16-bucket pow2-ns ladder (bucket `i` upper bound `2^(16+i)` ns;
    /// bucket 15 = `+Inf`; the 3 s blackout class lands in bucket 15).
    /// Additive / defaulted for backward compat.
    /// pending_neigh dwell histogram (`now_ns - queued_ns` at resolve).
    #[serde(rename = "neighbor_pending_dwell_buckets", default)]
    pub neighbor_pending_dwell_buckets: Vec<u64>,
    #[serde(rename = "neighbor_pending_dwell_sum_ns", default)]
    pub neighbor_pending_dwell_sum_ns: u64,
    #[serde(rename = "neighbor_pending_dwell_count", default)]
    pub neighbor_pending_dwell_count: u64,
    /// Resolver single-key RTM_GETNEIGH round-trip-time histogram.
    #[serde(rename = "neighbor_resolver_get_rtt_buckets", default)]
    pub neighbor_resolver_get_rtt_buckets: Vec<u64>,
    #[serde(rename = "neighbor_resolver_get_rtt_sum_ns", default)]
    pub neighbor_resolver_get_rtt_sum_ns: u64,
    #[serde(rename = "neighbor_resolver_get_rtt_count", default)]
    pub neighbor_resolver_get_rtt_count: u64,
    /// pending_neigh timeout-drops + queue-depth high-water mark.
    #[serde(rename = "neighbor_pending_timeout_drops_total", default)]
    pub neighbor_pending_timeout_drops_total: u64,
    #[serde(rename = "neighbor_pending_max_depth", default)]
    pub neighbor_pending_max_depth: u64,
    /// #1771 §2.6: per-key resolver + §2.5 ENOBUFS-re-dump telemetry.
    /// `get_backoff_attempts` is the subset of resolver GET attempts
    /// that were backoff RETRIES (key re-admitted after the per-key
    /// rate-limit window). The `netlink_*` counters instrument the
    /// monitor thread's lost-notification self-heal: ENOBUFS receives,
    /// throttled upsert-only re-dumps issued, and dynamic-neighbor
    /// entries actually (re)added by re-dump replies. The two gauges are
    /// per-binding sums published at the ~65ms debug tick: distinct
    /// unresolved next-hop keys buffered in pending_neigh, and keys held
    /// in the negative caches (lazy-TTL upper bound). All additive /
    /// defaulted for backward compatibility.
    #[serde(rename = "neighbor_resolver_get_backoff_attempts_total", default)]
    pub neighbor_resolver_get_backoff_attempts_total: u64,
    #[serde(rename = "neighbor_netlink_enobufs_total", default)]
    pub neighbor_netlink_enobufs_total: u64,
    #[serde(rename = "neighbor_netlink_redumps_total", default)]
    pub neighbor_netlink_redumps_total: u64,
    #[serde(rename = "neighbor_netlink_redump_upserts_total", default)]
    pub neighbor_netlink_redump_upserts_total: u64,
    #[serde(rename = "neighbor_pending_keys", default)]
    pub neighbor_pending_keys: u64,
    #[serde(rename = "neg_neigh_keys", default)]
    pub neg_neigh_keys: u64,
    /// #802: focused per-binding ring-pressure view. Projected from the
    /// same `BindingLiveState` atomics that back `Self::bindings` — a
    /// compact snapshot of the counters an operator looks at first when
    /// triaging XSK ring saturation (TX full, sendto ENOBUFS, pending-
    /// overflow, fill-ring empty descs, outstanding-tx gauge). Keeping
    /// it as a parallel field (rather than only embedded in
    /// `bindings[].*`) lets the daemon pull just the triage counters on
    /// its poll path without deserializing every field on `BindingStatus`.
    /// #1865: per-WG-tunnel operator telemetry rows. Keyed by tunnel
    /// NAME (`tunnel`) — `tunnel_endpoint_id` is informational only
    /// because positional ids renumber across commits (#1873). Empty
    /// (and omitted — `skip_serializing_if`) when no WG tunnel is
    /// configured, so non-WG deployments stay wire-byte-identical to
    /// pre-#1865. Additive / defaulted for mixed-version compat.
    #[serde(rename = "wg_tunnels", default, skip_serializing_if = "Vec::is_empty")]
    pub wg_tunnels: Vec<WgTunnelStatus>,
    #[serde(rename = "per_binding", default, skip_serializing_if = "Vec::is_empty")]
    pub per_binding: Vec<BindingCountersSnapshot>,
    /// #1249: low-frequency debug snapshot mapping active flow-cache
    /// entries to the worker/RX queue that currently owns them. This
    /// is a diagnostic/status surface, not a scheduler input; workers
    /// publish bounded owned snapshots from their existing debug tick.
    #[serde(rename = "flow_worker_map", default)]
    pub flow_worker_map: Vec<FlowWorkerStatus>,
    #[serde(rename = "flow_worker_map_truncated", default)]
    pub flow_worker_map_truncated: bool,
    /// #1248: class-specific active-flow distribution for CoS
    /// fairness. Aggregated as `(ifindex, queue_id, worker_id) ->
    /// active distinct cached flows` from the same worker debug tick
    /// that publishes `active_flow_count`.
    #[serde(rename = "cos_active_flow_counts", default)]
    pub cos_active_flow_counts: Vec<CoSActiveFlowCountStatus>,
    #[serde(rename = "cos_active_flow_counts_truncated", default)]
    pub cos_active_flow_counts_truncated: bool,
    #[serde(rename = "ha_groups", default)]
    pub ha_groups: Vec<HAGroupStatus>,
    #[serde(default)]
    pub fabrics: Vec<FabricSnapshot>,
    #[serde(default)]
    pub queues: Vec<QueueStatus>,
    #[serde(default)]
    pub bindings: Vec<BindingStatus>,
    #[serde(rename = "recent_session_deltas", default)]
    pub recent_session_deltas: Vec<SessionDeltaInfo>,
    #[serde(rename = "recent_exceptions", default)]
    pub recent_exceptions: Vec<ExceptionStatus>,
    #[serde(rename = "cos_interfaces", default)]
    pub cos_interfaces: Vec<CoSInterfaceStatus>,
    #[serde(rename = "policy_rule_counters", default)]
    pub policy_rule_counters: Vec<PolicyRuleCounterStatus>,
    /// #2218: per-rule NAT translation hit counters (SNAT/DNAT/static),
    /// keyed by the compiler-assigned counter_id.
    #[serde(rename = "nat_rule_counters", default)]
    pub nat_rule_counters: Vec<NatRuleCounterStatus>,
    #[serde(rename = "filter_term_counters", default)]
    pub filter_term_counters: Vec<FirewallFilterTermCounterStatus>,
    /// #3651: per-zone ingress/egress traffic (packet + byte) volume, summed
    /// across every worker/binding by the helper (`ProcessStatus`-level
    /// pre-summed sparse block — one row per zone with nonzero traffic, keyed
    /// by the stable zone id). The Go control plane mirrors each row into the
    /// legacy `dataplane.Manager` zone-counter offset map via
    /// `ReplaceZoneCounterOffsets` (#6843: the whole map is replaced per poll,
    /// so a zone the helper stops publishing stops being reported rather than
    /// freezing at its last value), so `show security zones` (Traffic
    /// statistics),
    /// the REST `/security/zones` endpoint, and the Prometheus collector report
    /// live per-zone volume instead of `ErrCounterNotPopulated` ("not
    /// available"). `zone_counter_layout_version` selects the decode path
    /// (0/absent = pre-#3651 helper, no per-zone data); a nonzero
    /// `zone_counter_overflow_active` means the configured zone count exceeded
    /// the helper's dense hot-path slot capacity and some zones went uncounted.
    #[serde(
        rename = "zone_counter_layout_version",
        default,
        skip_serializing_if = "crate::protocol::u32_is_zero"
    )]
    pub zone_counter_layout_version: u32,
    #[serde(
        rename = "zone_counter_overflow_active",
        default,
        skip_serializing_if = "crate::protocol::bool_is_false"
    )]
    pub zone_counter_overflow_active: bool,
    #[serde(rename = "zone_traffic_counters", default)]
    pub zone_traffic_counters: Vec<ZoneTrafficCounterStatus>,
    /// #3651: per-zone SYN/ICMP/UDP flood-EVENT counts, summed across every
    /// worker by the helper (one `ProcessStatus`-level pre-summed sparse block,
    /// one row per zone with nonzero flood drops, keyed by the stable zone id).
    /// The Go control plane mirrors each row into the legacy
    /// `dataplane.Manager` flood-counter offset map via
    /// `ReplaceFloodCounterOffsets` (the whole map is replaced per poll, so a
    /// zone the helper stops publishing stops being reported rather than
    /// freezing at its last value), so `show security screen ids-option
    /// statistics` reports live per-zone flood counts instead of
    /// `ErrCounterNotPopulated` ("not available").
    /// `flood_counter_layout_version` selects the decode path (0/absent =
    /// helper with no per-zone flood accounting); a true
    /// `flood_counter_overflow_active` means the configured zone count exceeded
    /// the helper's dense slot capacity and some zones went uncounted.
    #[serde(
        rename = "flood_counter_layout_version",
        default,
        skip_serializing_if = "crate::protocol::u32_is_zero"
    )]
    pub flood_counter_layout_version: u32,
    #[serde(
        rename = "flood_counter_overflow_active",
        default,
        skip_serializing_if = "crate::protocol::bool_is_false"
    )]
    pub flood_counter_overflow_active: bool,
    #[serde(rename = "zone_flood_counters", default)]
    pub zone_flood_counters: Vec<ZoneFloodCounterStatus>,
    #[serde(rename = "three_color_policer_counters", default)]
    pub three_color_policer_counters: Vec<ThreeColorPolicerStatus>,
    #[serde(rename = "source_nat_pools", default)]
    pub source_nat_pools: Vec<SourceNatPoolStatus>,
    #[serde(rename = "last_resolution", skip_serializing_if = "Option::is_none")]
    pub last_resolution: Option<PacketResolution>,
    #[serde(rename = "slow_path", default)]
    pub slow_path: SlowPathStatus,
    #[serde(rename = "debug_worker_threads", default)]
    pub debug_worker_threads: usize,
    #[serde(rename = "debug_identity_slots", default)]
    pub debug_identity_slots: usize,
    #[serde(rename = "debug_live_slots", default)]
    pub debug_live_slots: usize,
    #[serde(rename = "debug_planned_workers", default)]
    pub debug_planned_workers: usize,
    #[serde(rename = "debug_planned_bindings", default)]
    pub debug_planned_bindings: usize,
    #[serde(rename = "debug_reconcile_calls", default)]
    pub debug_reconcile_calls: u64,
    #[serde(rename = "debug_reconcile_stage", default)]
    pub debug_reconcile_stage: String,
    #[serde(rename = "event_stream_connected", default)]
    pub event_stream_connected: bool,
    #[serde(rename = "event_stream_seq", default)]
    pub event_stream_seq: u64,
    #[serde(rename = "event_stream_acked", default)]
    pub event_stream_acked: u64,
    #[serde(rename = "event_stream_sent", default)]
    pub event_stream_sent: u64,
    #[serde(rename = "event_stream_dropped", default)]
    pub event_stream_dropped: u64,
    /// I/O cycles in which the event-stream socket-write backlog hit its cap
    /// and the helper stopped draining the channel (stalled daemon reader,
    /// #2381). Growing → telemetry shed at the bounded channel; dataplane
    /// unaffected.
    #[serde(rename = "event_stream_write_stalls", default)]
    pub event_stream_write_stalls: u64,
    /// Accepted RT_FLOW / dataplane-telemetry frames evicted from the helper's
    /// replay buffer when it wrapped at capacity before the daemon ACKed them
    /// (#2382). These were counted in `event_stream_sent` at enqueue but are
    /// permanently lost after reconnect. A non-zero, growing value means
    /// telemetry was dropped via replay-buffer eviction (a disconnected or
    /// non-ACKing daemon let the window wrap). Distinct from ACK-trim, which
    /// is normal acknowledged-frame removal and is NOT counted here.
    #[serde(rename = "event_stream_replay_evictions", default)]
    pub event_stream_replay_evictions: u64,
    /// MSG_ACK control frames rejected because the daemon ACKed a sequence
    /// outside the valid `[acked_seq, next_seq]` window — a backward ACK
    /// (`seq < acked`) or a future ACK of a sequence never allocated
    /// (`seq > next`) (#2959). The helper fails closed and ignores such an
    /// ACK (watermark + replay buffer left intact). A non-zero, growing value
    /// means a buggy / mixed-version / corrupted daemon listener is emitting
    /// impossible ACK watermarks.
    #[serde(rename = "event_stream_invalid_acks", default)]
    pub event_stream_invalid_acks: u64,
    /// #2512: per-kind producer-side accounting for the RT_FLOW SESSION_CLOSE
    /// (type 14) and SESSION_CREATE (type 15) frames. Before #2512 these used
    /// a bare `try_send` that did not pass through the per-kind rate limiter,
    /// queue budget, or sent/dropped counters, so a dropped close/create was
    /// invisible. `_sent` is frames accepted onto the event channel; `_dropped`
    /// sums rate-limited + queue-full + disconnected drops for that kind. A
    /// dropped SESSION_CLOSE loses only one flow-export/syslog record — the
    /// type-2 HA session-sync close delta rides a separate frame and is never
    /// rate-limited (`push_delta`), so the consumer session state self-heals
    /// via the 1s session sweep.
    #[serde(rename = "event_stream_session_close_sent", default)]
    pub event_stream_session_close_sent: u64,
    #[serde(rename = "event_stream_session_close_dropped", default)]
    pub event_stream_session_close_dropped: u64,
    #[serde(rename = "event_stream_session_create_sent", default)]
    pub event_stream_session_create_sent: u64,
    #[serde(rename = "event_stream_session_create_dropped", default)]
    pub event_stream_session_create_dropped: u64,
    /// Monotonic timestamp (secs) of the last HA flow cache flush (#312).
    #[serde(rename = "last_cache_flush_at", default)]
    pub last_cache_flush_at: u64,
    /// #3773 (M13): cumulative count of fabric links skipped during a
    /// forwarding build/refresh because a value was MALFORMED — an invalid
    /// parent ifindex, an unparseable peer address, or a NON-EMPTY local/peer
    /// MAC string that failed to parse. A non-zero (especially climbing) value
    /// is a fabric config/environment fault an operator must fix; the helper
    /// journal names which fabric and why. Additive / defaulted for
    /// mixed-version compat.
    #[serde(rename = "fabric_link_skipped_malformed_total", default)]
    pub fabric_link_skipped_malformed_total: u64,
    /// #3773 (M13): cumulative count of fabric links skipped because the peer
    /// or local MAC was UNRESOLVED — an EMPTY MAC field still awaiting
    /// neighbor/interface resolution (the expected late-resolution
    /// `SyncFabricState` transient). Briefly non-zero at startup is normal; a
    /// PERSISTENTLY climbing value means a fabric peer is not resolving. A
    /// distinct, non-malformed state per #3773.
    #[serde(rename = "fabric_link_unresolved_peer_total", default)]
    pub fabric_link_unresolved_peer_total: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SlowPathStatus {
    #[serde(default)]
    pub active: bool,
    /// #2471: active but the live TUN MTU is below the configured MTU because
    /// the MTU-programming ioctl failed. Jumbo reinjection is refused.
    #[serde(rename = "degraded", default)]
    pub degraded: bool,
    /// #2471: the live TUN MTU (1500 fallback when programming failed).
    #[serde(rename = "live_mtu", default)]
    pub live_mtu: i32,
    #[serde(rename = "device_name", default)]
    pub device_name: String,
    #[serde(default)]
    pub mode: String,
    #[serde(rename = "last_error", default)]
    pub last_error: String,
    #[serde(rename = "queued_packets", default)]
    pub queued_packets: u64,
    #[serde(rename = "injected_packets", default)]
    pub injected_packets: u64,
    #[serde(rename = "injected_bytes", default)]
    pub injected_bytes: u64,
    #[serde(rename = "dropped_packets", default)]
    pub dropped_packets: u64,
    #[serde(rename = "dropped_bytes", default)]
    pub dropped_bytes: u64,
    #[serde(rename = "rate_limited_packets", default)]
    pub rate_limited_packets: u64,
    #[serde(rename = "queue_full_packets", default)]
    pub queue_full_packets: u64,
    #[serde(rename = "write_errors", default)]
    pub write_errors: u64,
    /// #2471: frames refused at enqueue because they exceed the live TUN MTU.
    #[serde(rename = "mtu_dropped_packets", default)]
    pub mtu_dropped_packets: u64,
}

impl From<crate::slowpath::SlowPathStatus> for SlowPathStatus {
    fn from(value: crate::slowpath::SlowPathStatus) -> Self {
        Self {
            active: value.active,
            degraded: value.degraded,
            live_mtu: value.live_mtu,
            device_name: value.device_name,
            mode: value.mode,
            last_error: value.last_error,
            queued_packets: value.queued_packets,
            injected_packets: value.injected_packets,
            injected_bytes: value.injected_bytes,
            dropped_packets: value.dropped_packets,
            dropped_bytes: value.dropped_bytes,
            rate_limited_packets: value.rate_limited_packets,
            queue_full_packets: value.queue_full_packets,
            write_errors: value.write_errors,
            mtu_dropped_packets: value.mtu_dropped_packets,
        }
    }
}

/// #1434: one WG PEER's telemetry row inside a `WgTunnelStatus`. The
/// Go mirror is `WgPeerStatus` in `pkg/dataplane/userspace/protocol.go`
/// — keep json tags identical on both sides. Fields are serde-defaulted
/// for mixed-version compat.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct WgPeerStatus {
    /// Peer static public key, 64-char lowercase hex (same rendering as
    /// the config-side `wg_peer_pubkey_hex`). Public by definition.
    /// NOTE: `wg show` renders base64; xpf surfaces are uniformly hex.
    #[serde(rename = "peer_pubkey_hex", default)]
    pub peer_pubkey_hex: String,
    /// Configured-or-learned peer endpoint (empty for a responder-only
    /// peer with no learned endpoint yet).
    #[serde(rename = "peer_endpoint", default)]
    pub peer_endpoint: String,
    /// Whether this peer currently holds a CONFIRMED (egress-usable)
    /// transport session.
    #[serde(rename = "session_confirmed", default)]
    pub session_confirmed: bool,
}

/// #1865: one WG tunnel's telemetry row inside `ProcessStatus`.
/// Counter semantics, lifetime, and the reserved-reason list live in
/// `afxdp/wg/counters.rs` (the single source of truth this mirrors);
/// the Go mirror is `WgTunnelStatus` in
/// `pkg/dataplane/userspace/protocol.go` — keep json tags identical
/// on BOTH sides (feedback_wire_protocol_both_sides). All fields are
/// serde-defaulted; rows are additive for mixed-version compat.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct WgTunnelStatus {
    /// Tunnel interface name (e.g. "wg0") — the PRIMARY key and the
    /// only Prometheus label. Falls back to `wg-endpoint-<id>` when
    /// the ifindex has no resolved name (a row is never dropped).
    #[serde(default)]
    pub tunnel: String,
    /// Positional endpoint id — informational cross-ref ONLY (#1873:
    /// renumbers when tunnels are added/removed; never a join key).
    #[serde(rename = "tunnel_endpoint_id", default)]
    pub tunnel_endpoint_id: u16,
    #[serde(rename = "listen_port", default)]
    pub listen_port: u16,
    /// Our LOCAL static public key, 64-char lowercase hex (#1434
    /// Increment 1). This is the key an operator must hand to the peer
    /// to configure us — derived once from the local private key at
    /// engine construction (`WgEngine::local_public_key`). Travels as a
    /// hex STRING (never a `Vec<u8>`, to avoid the Go↔Rust base64 wire
    /// trap, MEMORY #1961); operator surfaces re-render it as
    /// WireGuard-canonical base64. `#[serde(default)]` keeps a pre-#1434
    /// payload (key absent) decoding to "".
    #[serde(rename = "local_pubkey_hex", default)]
    pub local_pubkey_hex: String,
    /// Per-peer rows (#1434 multi-peer). Replaces the scalar
    /// peer_pubkey_hex / peer_endpoint / session_confirmed fields with
    /// one row per configured peer. The COUNTERS below remain
    /// tunnel-level (per-engine), as they were pre-#1434.
    #[serde(rename = "peers", default)]
    pub peers: Vec<WgPeerStatus>,
    /// Wall-clock epoch seconds of the most recent handshake
    /// completion (either role). 0 = never (epoch 0 is unreachable, so
    /// the sentinel is unambiguous without Option plumbing). Converted
    /// from the engine's monotonic stamp at snapshot time; an NTP step
    /// skews the display, never the stored stamp.
    #[serde(rename = "last_handshake_unix_secs", default)]
    pub last_handshake_unix_secs: u64,
    // --- handshake counters ---
    #[serde(rename = "hs_initiations_created", default)]
    pub hs_initiations_created: u64,
    #[serde(rename = "hs_initiation_build_failures", default)]
    pub hs_initiation_build_failures: u64,
    #[serde(rename = "hs_responses_created", default)]
    pub hs_responses_created: u64,
    #[serde(rename = "hs_completions_initiator", default)]
    pub hs_completions_initiator: u64,
    #[serde(rename = "hs_rx_drops_mac1_mismatch", default)]
    pub hs_rx_drops_mac1_mismatch: u64,
    #[serde(rename = "hs_rx_drops_malformed", default)]
    pub hs_rx_drops_malformed: u64,
    #[serde(rename = "hs_rx_drops_crypto", default)]
    pub hs_rx_drops_crypto: u64,
    #[serde(rename = "hs_rx_drops_unknown_peer", default)]
    pub hs_rx_drops_unknown_peer: u64,
    #[serde(rename = "hs_rx_drops_stale_response", default)]
    pub hs_rx_drops_stale_response: u64,
    #[serde(rename = "hs_rx_drops_index_exhausted", default)]
    pub hs_rx_drops_index_exhausted: u64,
    /// #4092 responder handshake anti-replay rejects (TAI64N `<=`
    /// greatest accepted from the peer). Distinct from the transport
    /// `decap_drops_replay` counter.
    #[serde(rename = "hs_rx_drops_replayed_init", default)]
    pub hs_rx_drops_replayed_init: u64,
    #[serde(rename = "hs_rx_cookie_unsupported", default)]
    pub hs_rx_cookie_unsupported: u64,
    /// #4094 PR-B initiator-side cookie-replies successfully consumed
    /// (decrypted + stored, arming a valid MAC2 on the next initiation).
    #[serde(rename = "hs_rx_cookie_consumed", default)]
    pub hs_rx_cookie_consumed: u64,
    /// #4094 PR-A responder cookie-reply / MAC2 under-load DoS-mitigation
    /// accounting: cookie replies emitted, under-load initiations dropped
    /// for a missing/bad MAC2 (challenged), under-load initiations that
    /// carried a valid MAC2 and proceeded, and cookie replies suppressed by
    /// the per-window emission budget (`hs_cookie_reply_budget_drops` also
    /// folds in the #4332 per-source token-bucket throttle drops).
    #[serde(rename = "hs_cookie_replies_sent", default)]
    pub hs_cookie_replies_sent: u64,
    #[serde(rename = "hs_rx_under_load_no_mac2", default)]
    pub hs_rx_under_load_no_mac2: u64,
    #[serde(rename = "hs_rx_under_load_mac2_ok", default)]
    pub hs_rx_under_load_mac2_ok: u64,
    #[serde(rename = "hs_cookie_reply_budget_drops", default)]
    pub hs_cookie_reply_budget_drops: u64,
    #[serde(rename = "rx_unknown_type", default)]
    pub rx_unknown_type: u64,
    #[serde(rename = "hs_send_errors", default)]
    pub hs_send_errors: u64,
    #[serde(rename = "hs_requests_armed", default)]
    pub hs_requests_armed: u64,
    // --- transport decap ---
    #[serde(rename = "decap_packets", default)]
    pub decap_packets: u64,
    #[serde(rename = "decap_bytes", default)]
    pub decap_bytes: u64,
    #[serde(rename = "decap_keepalives", default)]
    pub decap_keepalives: u64,
    #[serde(rename = "decap_drops_malformed_header", default)]
    pub decap_drops_malformed_header: u64,
    #[serde(rename = "decap_drops_unknown_session", default)]
    pub decap_drops_unknown_session: u64,
    #[serde(rename = "decap_drops_counter_ceiling", default)]
    pub decap_drops_counter_ceiling: u64,
    #[serde(rename = "decap_drops_crypto", default)]
    pub decap_drops_crypto: u64,
    #[serde(rename = "decap_drops_replay", default)]
    pub decap_drops_replay: u64,
    #[serde(rename = "decap_drops_allowed_ips", default)]
    pub decap_drops_allowed_ips: u64,
    #[serde(rename = "decap_drops_malformed_inner", default)]
    pub decap_drops_malformed_inner: u64,
    #[serde(rename = "decap_drops_buffer", default)]
    pub decap_drops_buffer: u64,
    // --- transport encap ---
    #[serde(rename = "encap_packets", default)]
    pub encap_packets: u64,
    #[serde(rename = "encap_bytes", default)]
    pub encap_bytes: u64,
    #[serde(rename = "encap_drops_no_session", default)]
    pub encap_drops_no_session: u64,
    #[serde(rename = "encap_drops_unconfirmed", default)]
    pub encap_drops_unconfirmed: u64,
    #[serde(rename = "encap_drops_rekey_required", default)]
    pub encap_drops_rekey_required: u64,
    #[serde(rename = "encap_drops_other", default)]
    pub encap_drops_other: u64,
    #[serde(rename = "encap_mtu_drops", default)]
    pub encap_mtu_drops: u64,
    #[serde(rename = "transport_send_errors", default)]
    pub transport_send_errors: u64,
    #[serde(rename = "tun_write_errors", default)]
    pub tun_write_errors: u64,
    #[serde(rename = "tun_rx_drops_no_endpoint", default)]
    pub tun_rx_drops_no_endpoint: u64,
    // --- #1888 S5 timers ---
    #[serde(rename = "encap_drops_expired", default)]
    pub encap_drops_expired: u64,
    #[serde(rename = "decap_drops_expired", default)]
    pub decap_drops_expired: u64,
    #[serde(rename = "sessions_expired", default)]
    pub sessions_expired: u64,
    #[serde(rename = "rekeys_initiated_age", default)]
    pub rekeys_initiated_age: u64,
    #[serde(rename = "rekeys_initiated_dead_peer", default)]
    pub rekeys_initiated_dead_peer: u64,
    #[serde(rename = "rekeys_initiated_keepalive_no_session", default)]
    pub rekeys_initiated_keepalive_no_session: u64,
    #[serde(rename = "keepalives_tx_passive", default)]
    pub keepalives_tx_passive: u64,
    #[serde(rename = "keepalives_tx_persistent", default)]
    pub keepalives_tx_persistent: u64,
    #[serde(rename = "pending_aborted_attempt_window", default)]
    pub pending_aborted_attempt_window: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ControlResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ProcessStatus>,
    #[serde(
        rename = "session_deltas",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub session_deltas: Vec<SessionDeltaInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ForwardingControlRequest {
    #[serde(default)]
    pub armed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct HAStateUpdateRequest {
    #[serde(default)]
    pub groups: Vec<HAGroupStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct QueueControlRequest {
    #[serde(rename = "queue_id")]
    pub queue_id: u32,
    #[serde(default)]
    pub registered: bool,
    #[serde(default)]
    pub armed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct BindingControlRequest {
    pub slot: u32,
    #[serde(default)]
    pub registered: bool,
    #[serde(default)]
    pub armed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct InjectPacketRequest {
    pub slot: u32,
    #[serde(rename = "packet_length", default)]
    pub packet_length: u32,
    #[serde(rename = "addr_family", default)]
    pub addr_family: u8,
    #[serde(default)]
    pub protocol: u8,
    #[serde(rename = "config_generation", default)]
    pub config_generation: u64,
    #[serde(rename = "fib_generation", default)]
    pub fib_generation: u32,
    #[serde(rename = "metadata_valid", default)]
    pub metadata_valid: bool,
    #[serde(rename = "destination_ip", default)]
    pub destination_ip: String,
    #[serde(rename = "emit_on_wire", default)]
    pub emit_on_wire: bool,
    #[serde(rename = "tuple_metadata_version", default)]
    pub tuple_metadata_version: i32,
    #[serde(rename = "source_ip", default)]
    pub source_ip: String,
    #[serde(rename = "source_port", default)]
    pub source_port: Option<u16>,
    #[serde(rename = "destination_port", default)]
    pub destination_port: Option<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SessionSyncRequest {
    #[serde(default)]
    pub operation: String,
    #[serde(rename = "addr_family", default)]
    pub addr_family: u8,
    #[serde(default)]
    pub protocol: u8,
    #[serde(rename = "src_ip", default)]
    pub src_ip: String,
    #[serde(rename = "dst_ip", default)]
    pub dst_ip: String,
    #[serde(rename = "src_port", default)]
    pub src_port: u16,
    #[serde(rename = "dst_port", default)]
    pub dst_port: u16,
    /// Legacy zone-name field. New peers populate `ingress_zone_id`
    /// instead and may leave this empty; preserved for one-release
    /// peer-compat window.
    #[serde(rename = "ingress_zone", default)]
    pub ingress_zone: String,
    #[serde(rename = "egress_zone", default)]
    pub egress_zone: String,
    /// #919: zone IDs preferred over names. Receiving side prefers
    /// these when nonzero; falls back to name lookup via
    /// `zone_name_to_id` otherwise.
    #[serde(rename = "ingress_zone_id", default)]
    pub ingress_zone_id: u16,
    #[serde(rename = "egress_zone_id", default)]
    pub egress_zone_id: u16,
    #[serde(rename = "owner_rg_id", default)]
    pub owner_rg_id: i32,
    #[serde(rename = "egress_ifindex", default)]
    pub egress_ifindex: i32,
    #[serde(rename = "tx_ifindex", default)]
    pub tx_ifindex: i32,
    #[serde(rename = "tunnel_endpoint_id", default)]
    pub tunnel_endpoint_id: u16,
    #[serde(rename = "tx_vlan_id", default)]
    pub tx_vlan_id: u16,
    #[serde(rename = "next_hop", default)]
    pub next_hop: String,
    #[serde(rename = "neighbor_mac", default)]
    pub neighbor_mac: String,
    #[serde(rename = "src_mac", default)]
    pub src_mac: String,
    #[serde(rename = "nat_src_ip", default)]
    pub nat_src_ip: String,
    #[serde(rename = "nat_dst_ip", default)]
    pub nat_dst_ip: String,
    #[serde(rename = "nat_src_port", default)]
    pub nat_src_port: u16,
    #[serde(rename = "nat_dst_port", default)]
    pub nat_dst_port: u16,
    #[serde(rename = "fabric_ingress", default)]
    pub fabric_ingress: bool,
    #[serde(rename = "is_reverse", default)]
    pub is_reverse: bool,
    /// #2785: the admitting policy's per-policy `then log` selection,
    /// carried so a session synced to this node logs the same RT_FLOW
    /// SESSION_CREATE/CLOSE records after failover. `serde(default)` =>
    /// false on an old peer that omits the field (no per-policy log),
    /// which is bit-identical to pre-#2785 behavior (rolling-upgrade safe).
    #[serde(rename = "log_session_init", default)]
    pub log_session_init: bool,
    #[serde(rename = "log_session_close", default)]
    pub log_session_close: bool,
    /// #2170 HA install generation. Mirrors the Go cluster apply layer's
    /// per-(sender,key) monotonic generation so the helper's in-memory
    /// SyncedSessionEntry can enforce the same guard (belt-and-suspenders
    /// for helper-originated deletes and the delayed-stale-install
    /// variant). `serde(default)` => 0 on an old peer that omits the field,
    /// which falls back to unconditional behavior (rolling-upgrade safe).
    #[serde(default)]
    pub generation: u64,
    /// #3301: the admitting policy's ID (#3056 namespace), carried so a
    /// peer-PROMOTED session resolves the admitting policy on its live-session
    /// rows / RT_FLOW records instead of the `0` sentinel (which the Go side
    /// renders as the FIRST configured policy — a wrong attribution). The local
    /// helper stamps this in-process at install; this field carries it across
    /// the cross-node HA wire (#1961 both-sides discipline). `serde(default)`
    /// => 0 on an old peer that omits the field, which is the legitimate
    /// "unattributed / non-policy-forwarded" value, bit-identical to the
    /// pre-#3301 synced-session behavior (rolling-upgrade safe).
    #[serde(rename = "policy_id", default)]
    pub policy_id: u32,
    /// #3301: a 1-based handle to the admitting rule's per-rule hit counter
    /// (#3073 `PolicyState::hit_counter_by_idx`). Carried so a peer-promoted
    /// session increments the correct policy hit counter on EVERY forwarded
    /// packet after failover (the established fast path uses this idx) instead
    /// of leaving the rule uncounted until a local re-evaluation re-stamps it.
    /// HA requires identical config on both nodes, so the same policy snapshot
    /// resolves the same idx on the peer. `serde(default)` => 0 ("no per-rule
    /// counter") on an old peer, the pre-#3301 behavior (rolling-upgrade safe).
    #[serde(rename = "policy_counter_idx", default)]
    pub policy_counter_idx: u32,
    /// #3301: the admitting application term's per-application inactivity (idle)
    /// timeout in SECONDS (#3227). Carried so a peer-promoted short-timeout
    /// session ages out on the app's value rather than the global per-protocol
    /// timeout until a real-traffic refresh re-stamps it. The receiver converts
    /// seconds -> ns via `app_inactivity_timeout_ns`. `serde(default)` => 0 on
    /// an old peer, which maps to `None` (use the global timeout — pre-#3301
    /// behavior, rolling-upgrade safe).
    #[serde(rename = "inactivity_timeout", default)]
    pub inactivity_timeout: u32,
    /// #4565: the NAT64 translated pool SOURCE (dotted-quad IPv4 string). A
    /// non-empty value is the SIGNAL that this synced forward session is a NAT64
    /// cross-family translation: the receiver sets `nat.nat64`, rewrites the
    /// forward source to this v4 pool address, reconstructs the forward v4
    /// destination from the /96-embedded low 32 bits of the (v6) `dst_ip`, and
    /// rebuilds the RFC 6146 reverse (v4->v6) BIB — the original v6 src/dst are
    /// the synced forward `src_ip`/`dst_ip` themselves, so only this pool source
    /// (chosen by the active node's `allocate_source`, not embedded in the key)
    /// must ride the wire. Enables a peer-PROMOTED NAT64 session to reverse-
    /// translate its replies after failover, and arms #4564's standby port
    /// reservation (which gates on `nat.nat64`). `serde(default)` => "" on an
    /// old peer that omits it, decoding to "not NAT64" (rolling-upgrade safe).
    #[serde(rename = "nat64_snat_v4", default)]
    pub nat64_snat_v4: String,
    /// #5212: the ORIGINATING node's stable RT_FLOW session id
    /// (`SessionTable::alloc_session_id` namespace: worker id in the high 16
    /// bits + a per-worker monotonic counter). Carried across the cross-node HA
    /// wire so a peer-synced session ADOPTS the originating node's id rather than
    /// minting a fresh node-local one on import — the standby's SESSION_CLOSE
    /// RT_FLOW record then correlates with the primary's SESSION_CREATE across
    /// both HA nodes (an operator or a collector merging both streams sees one
    /// id per logical session). The receiver stamps this onto the imported entry
    /// (`build_synced_session_entry` -> `SessionInstall::session_id` ->
    /// `upsert_synced_with_origin`) when non-zero, else falls back to a fresh
    /// local id. `serde(default)` => 0 on an old peer that omits the field,
    /// which is the "no id carried" sentinel (a real id is never 0 — the
    /// allocator's counter starts at 1), bit-identical to the pre-#5212
    /// fresh-local-id import (rolling-upgrade safe).
    #[serde(rename = "session_id", default)]
    pub session_id: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SessionDeltaDrainRequest {
    #[serde(default)]
    pub max: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct SessionExportRequest {
    #[serde(rename = "owner_rgs", default)]
    pub owner_rgs: Vec<i32>,
    #[serde(default)]
    pub max: u32,
}
