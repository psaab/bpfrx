use super::*;

/// Cross-thread session-table state shared between the coordinator,
/// HA worker, and packet workers via `Arc<Mutex<...>>`.
///
/// The 3 session tables (synced + nat + forward-wire) plus the
/// owner-RG index live here together because they're written and
/// queried as a unit by the HA bulk-sync, incremental-sync, and
/// session-resolution paths. The `export_seq` counter is the
/// per-RG ack sequence number that pairs with the export ack
/// broadcast in HA `export_owner_rg_sessions`.
pub(in crate::afxdp) struct SessionManager {
    pub(in crate::afxdp) synced: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(in crate::afxdp) nat: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(in crate::afxdp) forward_wire: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(in crate::afxdp) owner_rg_indexes: SharedSessionOwnerRgIndexes,
    pub(in crate::afxdp) export_seq: AtomicU64,
}

impl SessionManager {
    pub(super) fn new() -> Self {
        Self {
            synced: Arc::new(Mutex::new(FastMap::default())),
            nat: Arc::new(Mutex::new(FastMap::default())),
            forward_wire: Arc::new(Mutex::new(FastMap::default())),
            owner_rg_indexes: SharedSessionOwnerRgIndexes::default(),
            export_seq: AtomicU64::new(0),
        }
    }
}
