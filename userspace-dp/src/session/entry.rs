// Public-facing session data types extracted from session/mod.rs (#1047 P2 step 2).
// Pure relocation — bodies are byte-for-byte identical; visibility is
// unchanged (everything was already pub(crate)).
//
// SessionEntry (the internal storage type) stays in mod.rs because its
// fields are file-private and accessed directly by SessionTable's impl.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessionDecision {
    pub(crate) resolution: ForwardingResolution,
    pub(crate) nat: NatDecision,
}

/// #919: zone names dropped from the fast path. `ingress_zone` and
/// `egress_zone` are now `u16` IDs that index into
/// `forwarding.zone_id_to_name` for slow-path consumers (logging,
/// gRPC export, status). `0` means "unknown / unset" (matches the
/// existing `UserspaceDpMeta.ingress_zone` default at afxdp/types/mod.rs:64).
/// Removing the `Arc<str>` saves 28 bytes per `SessionMetadata` and
/// eliminates the `LOCK XADD` atomic on every `metadata.clone()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionMetadata {
    pub(crate) ingress_zone: u16,
    pub(crate) egress_zone: u16,
    pub(crate) owner_rg_id: i32,
    pub(crate) fabric_ingress: bool,
    pub(crate) is_reverse: bool,
    /// For NAT64 sessions: stores original IPv6 addresses so reverse IPv4
    /// replies can be translated back.
    pub(crate) nat64_reverse: Option<Nat64ReverseInfo>,
    /// #2508: the admitting policy's per-policy RT_FLOW SYSLOG log
    /// selection (`then log session-init`/`session-close`). Stamped at
    /// install so the close-time delta (which no longer has the policy in
    /// hand) and the open-time delta can gate the per-policy RT_FLOW
    /// SYSLOG records. Independent of the global NetFlow/IPFIX close
    /// exporter (#2460), which observes every close regardless.
    pub(crate) log_session_init: bool,
    pub(crate) log_session_close: bool,
    /// #3056: the admitting policy's ID, in the same namespace Go assigns in
    /// `pkg/dataplane/userspace/policies.go` and pushes in the policy snapshot
    /// (mirrored back as `PolicyEvaluationResult.policy_id`). Stamped at install
    /// from the matched policy so the live-session BPF-compat publish
    /// (`show security flow session` rows) and the SESSION_CREATE RT_FLOW record
    /// reference the policy that admitted the flow instead of the `0` sentinel,
    /// which the Go side renders as the FIRST configured policy (policyID 0) — a
    /// wrong attribution. `0` remains the legitimate value for non-policy-
    /// forwarded sessions (firewall-local / neighbor-seed / fabric / tunnel).
    /// In-process only: `SessionMetadata` carries no serde, so this rides the
    /// shared-session map and sibling-worker replicas automatically but does NOT
    /// cross the cross-node HA `SessionDeltaInfo` wire (a deliberate follow-up —
    /// the close-event/rows on a peer-PROMOTED session still resolve `0` until
    /// the sync delta carries it; #1961 both-sides wire discipline).
    pub(crate) policy_id: u32,
    /// #3227: the admitting application term's per-application inactivity (idle)
    /// timeout in NANOSECONDS, stamped at install from the matched policy's
    /// `PolicyEvaluationResult.inactivity_timeout` (seconds → ns). `None` means
    /// "use the global per-protocol `SessionTimeouts`" — the historical
    /// behavior, byte-identical for every flow whose application has no custom
    /// `inactivity-timeout`. When `Some`, `session_timeout_ns` uses it as the
    /// ESTABLISHED/idle expiry for the session, so the conntrack GC ages the
    /// session out on the app's value instead of the global timeout (closing the
    /// legacy-eBPF `appTimeout` parity regression). It does NOT override the
    /// short TCP closing/RST reap windows, matching Junos (inactivity-timeout is
    /// the idle timeout of an established session). In-process only: like
    /// `policy_id`, this rides the shared-session map and worker replicas but
    /// does NOT cross the cross-node HA `SessionDeltaInfo` wire yet, so a
    /// peer-promoted session ages on the global timeout until a real-traffic
    /// refresh re-stamps it (a deliberate follow-up).
    pub(crate) inactivity_timeout_ns: Option<u64>,
    /// #3073: a stable 1-based handle to the admitting policy rule's per-rule
    /// hit counter (`PolicyState::rules[idx-1].hit_counter`, resolved via
    /// `PolicyState::hit_counter_by_idx`). Stamped at install from the matched
    /// policy's `PolicyEvaluationResult.policy_counter_idx`. The established
    /// fast path (`poll_descriptor` session-hit and the flow-cache hit replay)
    /// uses it to increment the admitting policy's packet/byte counters on
    /// EVERY packet, so `show security policies hit-count` reflects the traffic
    /// the rule actually carries instead of only the first frame of each flow
    /// (the pre-#3073 cold-path-only count). `0` means "no per-rule counter":
    /// the implicit default-policy and every non-policy-forwarded session
    /// (firewall-local / neighbor-seed / fabric / tunnel), which the fast path
    /// then leaves uncounted. The cold path still counts the first packet once
    /// in `try_match_rule`, so each packet is counted exactly once. In-process
    /// only: like `policy_id` (#3056), this rides the shared-session map and
    /// sibling-worker replicas but does NOT cross the cross-node HA
    /// `SessionDeltaInfo` wire — a peer-promoted session counts nothing on the
    /// promoting node's policy counter until a local re-evaluation re-stamps a
    /// handle (a deliberate follow-up, mirroring the #3056 wire note).
    pub(crate) policy_counter_idx: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionLookup {
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ForwardSessionMatch {
    pub(crate) key: SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionOrigin {
    ForwardFlow,
    ReverseFlow,
    LocalMiss,
    MissingNeighborSeed,
    SyncImport,
    SharedMaterialize,
    SharedPromote,
    #[allow(dead_code)] // enum variant for completeness
    WorkerLocalImport,
}

impl SessionOrigin {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ForwardFlow => "forward_flow",
            Self::ReverseFlow => "reverse_flow",
            Self::LocalMiss => "local_miss",
            Self::MissingNeighborSeed => "missing_neighbor_seed",
            Self::SyncImport => "sync_import",
            Self::SharedMaterialize => "shared_materialize",
            Self::SharedPromote => "shared_promote",
            Self::WorkerLocalImport => "worker_local_import",
        }
    }

    /// Returns true for origins that represent peer-synced sessions.
    /// These are sessions that arrived from the HA peer rather than
    /// being created by local traffic.
    pub(crate) fn is_peer_synced(self) -> bool {
        matches!(
            self,
            Self::SyncImport | Self::SharedMaterialize | Self::WorkerLocalImport
        )
    }

    pub(crate) fn is_promotable_synced(self) -> bool {
        matches!(self, Self::SyncImport | Self::SharedMaterialize)
    }

    pub(crate) fn worker_replica_origin(self) -> Self {
        if self.is_promotable_synced() {
            Self::SyncImport
        } else {
            Self::WorkerLocalImport
        }
    }

    pub(crate) fn materialized_shared_hit_origin(self) -> Self {
        if self.is_promotable_synced() {
            Self::SharedMaterialize
        } else {
            Self::WorkerLocalImport
        }
    }

    pub(crate) fn is_transient_local_seed(self) -> bool {
        matches!(self, Self::MissingNeighborSeed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionDeltaKind {
    Open,
    Close,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SessionDelta {
    pub(crate) kind: SessionDeltaKind,
    pub(crate) key: SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    pub(crate) origin: SessionOrigin,
    pub(crate) fabric_redirect_sync: bool,
    /// #2465: monotonic (`CLOCK_MONOTONIC`) nanosecond timestamp at which the
    /// session was first installed, copied from the `SessionEntry.created_ns`.
    /// Carried so the RT_FLOW SESSION_CLOSE frame can report a real flow
    /// StartTime instead of the packet-count heuristic. `0` means "unknown"
    /// (e.g. an explicit delete path that no longer has the entry, or an
    /// HA-synced delta that never had a local install) — the exporter falls
    /// back to `estimateSessionDuration` in that case.
    pub(crate) created_ns: u64,
    /// #2465: monotonic nanosecond timestamp of the session's last activity
    /// (`SessionEntry.last_seen_ns`) at close time. Used together with
    /// `created_ns` to convert the monotonic creation instant to an absolute
    /// wall-clock StartTime at emit time without depending on a wall-clock
    /// reading taken inside the GC pass. `0` means "unknown".
    pub(crate) last_seen_ns: u64,
    /// #2501: the session's per-direction byte/packet counters at the moment
    /// this delta was produced. Snapshotted from `SessionEntry.counters` so
    /// the SESSION_CLOSE RT_FLOW frame (#2460) reports real NetFlow/IPFIX
    /// volume in its already-reserved wire slots. Meaningful only on a Close
    /// delta sourced from a live local entry; an Open delta and a
    /// synthesized close that no longer has the entry carry the
    /// `Default` (all-zero) value, which keeps the prior on-wire behavior.
    pub(crate) counters: SessionCounters,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExpiredSession {
    pub(crate) key: SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    pub(crate) origin: SessionOrigin,
}
