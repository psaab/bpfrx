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
/// existing `UserspaceDpMeta.ingress_zone` default at types.rs:64).
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExpiredSession {
    pub(crate) key: SessionKey,
    pub(crate) decision: SessionDecision,
    pub(crate) metadata: SessionMetadata,
    pub(crate) origin: SessionOrigin,
}
