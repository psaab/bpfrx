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
///
/// The three sync-import refusal counters below are PER-INSTANCE
/// (`AtomicU64` fields, not process-global statics) for the same reason
/// `Coordinator::last_quiesce_ms` and the `force_worker_*` seams are: a
/// process-global counter is observable by every other `Coordinator` in the
/// process. Production builds exactly one `Coordinator` (`server::lifecycle`),
/// so the exported Prometheus value (`import_cap_drops`, via
/// `server/helpers/status.rs` -> `protocol::control` -> the Go collector) is
/// unchanged; the other two have no surface outside this binary at all — their
/// accessors are called only from `ha_tests.rs`. (None of the three is in
/// `proto/`: this crate has no gRPC dependency.) The change is observable only
/// to tests, which build one `Coordinator` per `#[test]` and run them
/// concurrently in a single process — as globals, every assertion about these
/// counters depended on what every other test happened to do (#6819).
pub(in crate::afxdp) struct SessionManager {
    pub(in crate::afxdp) synced: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(in crate::afxdp) nat: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(in crate::afxdp) forward_wire: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub(in crate::afxdp) owner_rg_indexes: SharedSessionOwnerRgIndexes,
    pub(in crate::afxdp) export_seq: AtomicU64,
    /// #2170 HA deferred-delete generation guard observability. These count how
    /// often the helper's in-memory SyncedSessionEntry generation guard refused
    /// a stale-generation install (`upsert_synced_session`, the
    /// delayed-stale-install variant) or a stale-generation delete
    /// (`delete_synced_session_gen`, belt-and-suspenders for any helper-side
    /// generation-aware delete). The authoritative guard lives in the Go
    /// cluster apply layer; these helper-side counters report any
    /// divergence/back-stop activity. Surfaced via
    /// `Coordinator::session_install_stale_ignored_total()` /
    /// `session_delete_stale_ignored_total()`.
    pub(in crate::afxdp) install_stale_ignored: AtomicU64,
    pub(in crate::afxdp) delete_stale_ignored: AtomicU64,
    /// #7209: peer-synced imports whose `(from_zone, to_zone)` pair could not
    /// be resolved locally, so the source-NAT reservation was booked WITHOUT
    /// #6211's zone narrowing.
    ///
    /// What the operator loses, which is what makes this worth a counter: the
    /// session is installed with the ACTIVE node's exact translated address and
    /// port — those come off the HA wire and are never recomputed, so nothing
    /// is mistranslated. What is lost is the narrowing that picks WHICH rule's
    /// allocator holds the reservation. With a single pool-mode rule owning the
    /// translated address the two paths agree and this is purely informational.
    /// It only diverges where two pool-mode rules' pools BOTH contain that
    /// address in separate allocators, and there the booking may sit in a
    /// different allocator than the active's — with a second booking taken if a
    /// later re-upsert does resolve, both live until teardown frees them and
    /// both counting against `max_tracked_flows`.
    ///
    /// Nonzero is not by itself a fault: it is expected while a config apply is
    /// in flight (`sync_session` reads the PUBLISHED forwarding view, which lags
    /// the pending one by design — #7209) and on an HA standby's first sync
    /// before any snapshot has been applied. Sustained growth on a settled
    /// config means the nodes' zone configuration has drifted.
    ///
    /// Surfaced via `Coordinator::synced_import_zone_unresolved_total()`.
    pub(in crate::afxdp) synced_import_zone_unresolved: AtomicU64,
    /// #5674: peer-synced session imports REJECTED by the coordinator's
    /// aggregate admission bound (`upsert_synced_session`). Locally-created
    /// sessions are capped per worker at `DEFAULT_MAX_SESSIONS`
    /// (`install_with_protocol_with_origin`), but peer-synced sessions were
    /// imported with NO cap and fanned out to EVERY worker command queue +
    /// table, so a peer under session-table pressure — or a
    /// malicious/compromised peer — could drive this node past its own
    /// aggregate session ceiling and multiply that state across all workers
    /// (the availability/DoS root of #5674). `upsert_synced_session` now bounds
    /// the shared synced map (the single fan-out choke point) at this
    /// appliance's OWN aggregate ENTRY ceiling (`2 * worker_count *
    /// DEFAULT_MAX_SESSIONS` — 2× the logical ceiling because each admitted
    /// forward logical session publishes a forward AND a synthesized reverse
    /// companion into the map) and drop-newest-rejects a NEW over-ceiling
    /// FORWARD key here (a REPLACE of an existing key, and a lone reverse
    /// import, never trip the bound — neither grows the forward-keyed count).
    /// Surfaced via `Coordinator::synced_import_cap_drops_total()` and the
    /// Prometheus counter `xpf_userspace_synced_import_cap_drops_total`. A
    /// nonzero value means a peer exceeded its own LOGICAL session ceiling (a
    /// malicious/compromised peer); a legitimate symmetric-pair failover — the
    /// peer's full logical set (N logical → 2N entries) EXACTLY fits the 2N cap
    /// — never trips it, at any peer load.
    pub(in crate::afxdp) import_cap_drops: AtomicU64,
    /// #6600: peer-synced imports REFUSED because this node could not reserve
    /// the translated NAT port the session names.
    ///
    /// The import path published the shared session entry BEFORE any worker
    /// reserved that port, and the reservation — which happens only inside the
    /// worker-local upsert — REFUSES to steal a port a different live
    /// allocation already holds. The refusal was returned by nothing, counted
    /// by nothing and logged by nothing, so in the window between publish and
    /// worker-apply a local flow could claim the port and the imported session
    /// went on advertising a translation this node did not own. Any packet
    /// forwarded on that shared-backed decision used it.
    ///
    /// The reservation now happens at the coordinator BEFORE the publish, and a
    /// refusal drops the import instead. That is the safe direction — no
    /// session beats a session naming someone else's port, and the peer re-syncs
    /// — but it is still a DROPPED failover session, so it must be visible: a
    /// silent drop would trade one invisible failure for another. A nonzero
    /// value means a local flow held the translated port at import time, which
    /// on a healthy standby (owning RG passive) should not happen and points at
    /// overlapping pools, an active-active RG pair sharing one SNAT pool, or
    /// genuine NAT config drift between the nodes.
    pub(in crate::afxdp) import_reserve_refused: AtomicU64,
}

impl SessionManager {
    pub(super) fn new() -> Self {
        Self {
            synced: Arc::new(Mutex::new(FastMap::default())),
            nat: Arc::new(Mutex::new(FastMap::default())),
            forward_wire: Arc::new(Mutex::new(FastMap::default())),
            owner_rg_indexes: SharedSessionOwnerRgIndexes::default(),
            export_seq: AtomicU64::new(0),
            install_stale_ignored: AtomicU64::new(0),
            synced_import_zone_unresolved: AtomicU64::new(0),
            delete_stale_ignored: AtomicU64::new(0),
            import_cap_drops: AtomicU64::new(0),
            import_reserve_refused: AtomicU64::new(0),
        }
    }
}
