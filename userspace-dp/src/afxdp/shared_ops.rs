use super::*;
use std::sync::atomic::AtomicU64;

/// #1760 W3': cumulative count of shared-map NAT reverse-key displacement
/// events — a `publish_shared_session` insert into `shared_nat_sessions`
/// (reverse-wire or reverse-canonical slot) displaced an entry whose
/// FORWARD key differs from the one being published. Two distinct forward
/// NAT sessions mapping onto one reply tuple K is the #1758/#1760 latent
/// 1:N collision. This is the single choke point every transit forward
/// NAT session passes through — normal installs, `MissingNeighborSeed`
/// installs (which are NOT replicated to sibling workers and therefore
/// invisible to the per-worker `nat_reverse_key_collisions` counter),
/// promotes, HA sync imports, and tunnel-local installs — so zero here is
/// a much stronger "no collision while this process was up" signal than
/// the per-worker counter alone. Same-session republish (promote, RG
/// migration, HA re-sync) displaces an entry with the SAME forward key
/// and is not counted; nor is the entry's own canonical/wire alias.
/// Event count, not a pair census: a standing collision against a live
/// session whose K was already removed (post-winner-expiry) is not
/// observable at this choke point — see
/// docs/research/1760-reverse-key-v2/plan.md §2.3. Surfaced as
/// `xpf_userspace_session_nat_reverse_key_shared_displacements_total`.
pub(crate) static NAT_REVERSE_KEY_SHARED_DISPLACEMENTS: AtomicU64 = AtomicU64::new(0);

/// #1760 W3' detection helper: count a shared-map displacement when the
/// displaced entry belongs to a DIFFERENT forward session. Shared by the
/// reverse-wire and reverse-canonical insert sites in
/// `publish_shared_session`.
///
/// Alias exclusion (Codex code-r1 F1): HA session sync deliberately
/// publishes a fabric-redirect session TWICE — canonical forward key plus
/// a NAT-translated forward-WIRE alias key carrying the same value
/// (`pkg/daemon/daemon_ha_userspace.go` `userspaceForwardWireAliasFromDeltaV4`,
/// queued under `delta.FabricRedirect && !delta.FabricIngress`). Both
/// forms derive the same reverse key K, so on a standby the pair would
/// displace each other at K every sync sweep — a same-logical-session
/// republish, not a 1:N collision. `forward_wire_key` is idempotent
/// (rewrites replace src/dst with the rewrite targets), so the alias
/// relation is exactly "one key is the other's forward-wire form".
/// Genuine colliding sessions keep counting: their CANONICAL keys are
/// not each other's wire forms (each wire form is the shared external
/// tuple, not the peer's internal tuple), and NAT-vs-different-NAT or
/// NAT-vs-no-NAT pairs whose keys ARE wire-related still count because
/// the alias test also requires an identical NatDecision (the HA alias
/// carries the same session value as its canonical form).
/// Known accepted under-count:
/// on a standby, a genuine collision involving a wire-FORM synced entry
/// is excluded by this test — the session's OWNER node still counts the
/// canonical-vs-canonical displacement in its own shared map.
#[inline]
fn record_shared_nat_displacement(
    displaced: Option<&SyncedSessionEntry>,
    entry: &SyncedSessionEntry,
) {
    let Some(existing) = displaced else {
        return;
    };
    if existing.key == entry.key {
        return;
    }
    // Wire-alias relation: same logical session under its translated key.
    // The HA alias is queued with the SAME session value as its canonical
    // form, so its NatDecision is identical — requiring NAT equality keeps
    // genuine NAT-vs-different-NAT (and NAT-vs-no-NAT direct) collisions
    // counted even though their keys are also wire-related (Codex code-r2:
    // DNAT client->VIP rewritten to client->backend vs a direct no-NAT
    // client->backend flow is a REAL collision and must count).
    if existing.decision.nat == entry.decision.nat
        && (existing.key == forward_wire_key(&entry.key, entry.decision.nat)
            || entry.key == forward_wire_key(&existing.key, existing.decision.nat))
    {
        return;
    }
    NAT_REVERSE_KEY_SHARED_DISPLACEMENTS.fetch_add(1, Ordering::Relaxed);
}

/// #1760 W1: last-warn timestamp for the journald reverse-key-collision
/// warn. Process-global so the ≤1 line/min bound holds regardless of
/// worker count (AGY r1 F4).
static NAT_REVERSE_KEY_WARN_LAST_NS: AtomicU64 = AtomicU64::new(0);

/// #1760 W1: minimum interval between journald collision warns.
const NAT_REVERSE_KEY_WARN_INTERVAL_NS: u64 = 60_000_000_000;

/// #1760 W1: claim the process-global collision-warn slot. Returns true
/// when the caller won and may emit the warn; false when inside the 60s
/// window or another worker won the race. Same load → window-check → CAS
/// shape as the coordinator warm-sweep throttle
/// (`coordinator/mod.rs` `last_warm_sweep_ns`): a lost CAS means another
/// thread claimed this slot concurrently, which is exactly the
/// "already warned" outcome we want.
pub(crate) fn try_claim_nat_reverse_key_warn(now_ns: u64) -> bool {
    let last = NAT_REVERSE_KEY_WARN_LAST_NS.load(Ordering::Acquire);
    if now_ns.saturating_sub(last) < NAT_REVERSE_KEY_WARN_INTERVAL_NS {
        return false;
    }
    NAT_REVERSE_KEY_WARN_LAST_NS
        .compare_exchange(last, now_ns, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

pub(super) fn demote_shared_owner_rgs(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    owner_rgs: &[i32],
) {
    if owner_rgs.is_empty() {
        return;
    }
    let mut demoted_entries = Vec::new();
    if let Ok(mut sessions) = shared_sessions.lock() {
        for key in owner_rg_session_keys(&shared_owner_rg_indexes.sessions, owner_rgs) {
            if let Some(entry) = sessions.get_mut(&key) {
                let previous = entry.clone();
                entry.origin = SessionOrigin::SyncImport;
                demoted_entries.push((previous, entry.clone()));
            }
        }
    }
    for (previous, entry) in demoted_entries {
        refresh_reverse_prewarm_owner_rg_indexes(
            &shared_owner_rg_indexes.reverse_prewarm_sessions,
            forwarding,
            dynamic_neighbors,
            Some(&previous),
            Some(&entry),
        );
    }
    if let Ok(mut sessions) = shared_nat_sessions.lock() {
        for key in owner_rg_session_keys(&shared_owner_rg_indexes.nat_sessions, owner_rgs) {
            if let Some(entry) = sessions.get_mut(&key) {
                entry.origin = SessionOrigin::SyncImport;
            }
        }
    }
    if let Ok(mut sessions) = shared_forward_wire_sessions.lock() {
        for key in owner_rg_session_keys(&shared_owner_rg_indexes.forward_wire_sessions, owner_rgs)
        {
            if let Some(entry) = sessions.get_mut(&key) {
                entry.origin = SessionOrigin::SyncImport;
            }
        }
    }
}

pub(super) fn synced_replica_entry(entry: &SyncedSessionEntry) -> SyncedSessionEntry {
    let mut replica = entry.clone();
    replica.origin = entry.origin.worker_replica_origin();
    replica
}

/// Pre-warm reverse companions in shared session maps at RG activation.
///
/// With deterministic reverse companions (#310), the Go sync path already
/// pre-installs reverse entries via UpsertSynced. This function still runs
/// at activation to re-resolve egress with local forwarding state (the
/// pre-installed entries carry the peer's interface indices/MACs).
///
/// Use the union of the shared owner-RG session index and the narrower
/// reverse-prewarm index here. Activation is infrequent, and locally promoted
/// sessions can exist in the shared table without appearing in the
/// reverse-prewarm subset, while split-RG reverse companions can still resolve
/// to an activated RG even when the forward entry's current owner RG is
/// different. Both cases need their forward entries restored to worker
/// SessionTables and, when applicable, their reverse companions synthesized
/// again on activation.
pub(super) fn prewarm_reverse_synced_sessions_for_owner_rgs(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    session_map_fd: c_int,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    owner_rgs: &[i32],
    now_secs: u64,
) {
    if owner_rgs.is_empty() {
        return;
    }
    let publish_session_map = session_map_fd >= 0;
    let owner_rg_set: std::collections::BTreeSet<i32> = owner_rgs.iter().copied().collect();
    let mut candidate_keys = owner_rg_session_keys_serialized(
        shared_sessions,
        &shared_owner_rg_indexes.sessions,
        owner_rgs,
    );
    let reverse_candidate_keys = owner_rg_session_keys_serialized(
        shared_sessions,
        &shared_owner_rg_indexes.reverse_prewarm_sessions,
        owner_rgs,
    );
    for key in reverse_candidate_keys {
        if !candidate_keys.contains(&key) {
            candidate_keys.push(key);
        }
    }
    let (forward_entries, reverse_entries) = shared_sessions
        .lock()
        .map(|sessions| {
            let mut forward_entries = Vec::new();
            let mut reverse_entries = Vec::new();
            for key in candidate_keys {
                let Some(entry) = sessions.get(&key) else {
                    continue;
                };
                if entry.metadata.is_reverse {
                    continue;
                }
                let allow_reverse_prewarm = entry.origin.is_peer_synced()
                    || matches!(entry.origin, SessionOrigin::SharedPromote);
                let Some(reverse) = synthesized_synced_reverse_entry(
                    forwarding,
                    ha_state,
                    dynamic_neighbors,
                    entry,
                    now_secs,
                ) else {
                    // Collect forward entry even if reverse can't be synthesized,
                    // as long as the forward session belongs to an activated RG.
                    if owner_rg_set.contains(&entry.metadata.owner_rg_id) {
                        forward_entries.push(entry.clone());
                    }
                    continue;
                };
                if owner_rg_set.contains(&entry.metadata.owner_rg_id)
                    || owner_rg_set.contains(&reverse.metadata.owner_rg_id)
                {
                    forward_entries.push(entry.clone());
                    if allow_reverse_prewarm {
                        reverse_entries.push(reverse);
                    }
                }
            }
            (forward_entries, reverse_entries)
        })
        .unwrap_or_default();
    if forward_entries.is_empty() && reverse_entries.is_empty() {
        return;
    }
    // Push forward entries to workers so their local SessionTables have
    // the promoted sessions. Without this, workers only have reverse
    // sessions and incoming traffic on existing flows misses the forward
    // session lookup.
    //
    // Also publish forward sessions to the USERSPACE_SESSIONS BPF map
    // synchronously (#475). Without this, there is a window between RG
    // activation and the workers processing UpsertSynced where the XDP
    // shim has no REDIRECT entry for forward flows. Packets arrive as
    // session misses and can resolve to HAInactive if the worker hasn't
    // yet applied the HA state update.
    let mut fwd_publish_errors = 0u32;
    for forward in &forward_entries {
        if publish_session_map
            && publish_session_map_entry_for_session(
                session_map_fd,
                &forward.key,
                forward.decision,
                &forward.metadata,
            )
            .is_err()
        {
            fwd_publish_errors += 1;
            // #1789: fold the activation-prewarm forward publish failures
            // into the global publish-error total. Semantically identical
            // to every other counted site (a USERSPACE_SESSIONS publish
            // that returned Err); the local fwd_publish_errors count is
            // kept only for the existing one-shot eprintln below, so this
            // is one increment per failure, not a double count.
            SESSION_PUBLISH_ERRORS_SHARED.fetch_add(1, Ordering::Relaxed);
        }
        for commands in worker_commands {
            // #1807: recover-and-push — `if let Ok` silently DROPPED the
            // activation-prewarm UpsertSynced for a poisoned worker queue.
            let mut pending = worker_queue::lock_recover(commands);
            pending.push_back(WorkerCommand::UpsertSynced(forward.clone()));
        }
    }
    if fwd_publish_errors > 0 {
        eprintln!(
            "xpf-ha: prewarm forward BPF publish: {} errors out of {} entries",
            fwd_publish_errors,
            forward_entries.len()
        );
    }
    for reverse in reverse_entries {
        publish_shared_session(
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            &reverse,
        );
        if publish_session_map {
            // #1789: the reverse-prewarm publish in the same activation
            // path was still swallowed with `let _ =`; count it like the
            // forward loop above.
            if publish_session_map_entry_for_session(
                session_map_fd,
                &reverse.key,
                reverse.decision,
                &reverse.metadata,
            )
            .is_err()
            {
                SESSION_PUBLISH_ERRORS_SHARED.fetch_add(1, Ordering::Relaxed);
            }
        }
        for commands in worker_commands {
            // #1807: recover-and-push — `if let Ok` silently DROPPED the
            // reverse-prewarm UpsertSynced for a poisoned worker queue.
            let mut pending = worker_queue::lock_recover(commands);
            pending.push_back(WorkerCommand::UpsertSynced(reverse.clone()));
        }
    }
}

/// Republish USERSPACE_SESSIONS BPF map entries for ALL shared sessions
/// belonging to the given owner RGs.
///
/// Called during RG activation (#475) to close the gap where sessions
/// exist in the shared table (received via sync) but their BPF map entries
/// were deleted during the previous demotion cycle. The `reverse_prewarm`
/// index only covers sessions added via `upsert_synced_session` — locally
/// originated sessions that were demoted then re-synced may not appear
/// there. This function uses the comprehensive `sessions` owner-RG index
/// to ensure no session is missed.
pub(super) fn republish_bpf_session_entries_for_owner_rgs(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    session_map_fd: c_int,
    owner_rgs: &[i32],
) -> u32 {
    if owner_rgs.is_empty() {
        return 0;
    }
    let keys = owner_rg_session_keys_serialized(
        shared_sessions,
        &shared_owner_rg_indexes.sessions,
        owner_rgs,
    );
    // Collect entries under the lock, then release before BPF syscalls
    // to avoid blocking concurrent session insert/remove/lookup.
    let entries: Vec<_> = {
        let sessions = match shared_sessions.lock() {
            Ok(s) => s,
            Err(_) => return 0,
        };
        keys.iter()
            .filter_map(|key| {
                sessions
                    .get(key)
                    .map(|e| (e.key.clone(), e.decision, e.metadata.clone()))
            })
            .collect()
    };
    let mut published = 0u32;
    let mut errors = 0u32;
    for (key, decision, metadata) in &entries {
        if publish_session_map_entry_for_session(session_map_fd, key, *decision, metadata).is_ok() {
            published += 1;
        } else {
            errors += 1;
            // #1789: feed the activation-republish failures into the same
            // always-on total as every other USERSPACE_SESSIONS publish site.
            SESSION_PUBLISH_ERRORS_SHARED.fetch_add(1, Ordering::Relaxed);
        }
    }
    if errors > 0 {
        eprintln!(
            "xpf-ha: republish_bpf_session_entries: {} errors out of {} attempted",
            errors,
            published + errors
        );
    }
    published
}

pub(super) fn lookup_shared_session(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    key: &SessionKey,
) -> Option<SyncedSessionEntry> {
    shared_sessions
        .lock()
        .ok()
        .and_then(|sessions| sessions.get(key).cloned())
}

pub(super) fn lookup_shared_forward_nat_match(
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    reply_key: &SessionKey,
) -> Option<SyncedSessionEntry> {
    shared_nat_sessions
        .lock()
        .ok()
        .and_then(|sessions| sessions.get(reply_key).cloned())
}

pub(super) fn lookup_shared_forward_wire_match(
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    wire_key: &SessionKey,
) -> Option<SyncedSessionEntry> {
    shared_forward_wire_sessions
        .lock()
        .ok()
        .and_then(|sessions| sessions.get(wire_key).cloned())
}

#[derive(Clone, Debug)]
pub(super) enum ResolvedSessionKey {
    QueryKey,
    Canonical(SessionKey),
}

impl ResolvedSessionKey {
    pub(super) fn as_ref<'a>(&'a self, query_key: &'a SessionKey) -> &'a SessionKey {
        match self {
            Self::QueryKey => query_key,
            Self::Canonical(key) => key,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct ResolvedSessionLookup {
    pub(super) key: ResolvedSessionKey,
    pub(super) lookup: SessionLookup,
    pub(super) shared_entry: Option<SyncedSessionEntry>,
    pub(super) origin: SessionOrigin,
}

impl ResolvedSessionLookup {
    pub(super) fn local_query(lookup: SessionLookup, origin: SessionOrigin) -> Self {
        Self {
            key: ResolvedSessionKey::QueryKey,
            lookup,
            shared_entry: None,
            origin,
        }
    }

    pub(super) fn local(key: SessionKey, lookup: SessionLookup, origin: SessionOrigin) -> Self {
        Self {
            key: ResolvedSessionKey::Canonical(key),
            lookup,
            shared_entry: None,
            origin,
        }
    }

    pub(super) fn shared(entry: SyncedSessionEntry) -> Self {
        let origin = entry.origin;
        Self {
            key: ResolvedSessionKey::Canonical(entry.key.clone()),
            lookup: SessionLookup {
                decision: entry.decision,
                metadata: entry.metadata.clone(),
            },
            shared_entry: Some(entry),
            origin,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct ResolvedFlowSessionDecision {
    pub(super) key: SessionKey,
    pub(super) decision: SessionDecision,
    pub(super) metadata: SessionMetadata,
    pub(super) origin: SessionOrigin,
    pub(super) created: bool,
}

// Fabric-ingress SNAT-only forward entries are standby-side wire placeholders
// in the split-RG topology: they should not win lookups over the real shared
// session and should not synthesize a competing local reverse session.
pub(super) fn is_fabric_wire_placeholder(
    fabric_ingress: bool,
    is_reverse: bool,
    decision: SessionDecision,
) -> bool {
    fabric_ingress
        && !is_reverse
        && decision.nat.rewrite_src.is_some()
        && decision.nat.rewrite_dst.is_none()
}

pub(super) fn lookup_session_across_scopes(
    sessions: &mut SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    key: &SessionKey,
    now_ns: u64,
    tcp_flags: u8,
) -> Option<ResolvedSessionLookup> {
    if let Some((lookup, origin)) = sessions.lookup_with_origin(key, now_ns, tcp_flags) {
        if is_fabric_wire_placeholder(
            lookup.metadata.fabric_ingress,
            lookup.metadata.is_reverse,
            lookup.decision,
        ) && let Some(shared) =
            lookup_shared_forward_wire_match(shared_forward_wire_sessions, key)
        {
            return Some(ResolvedSessionLookup::shared(shared));
        }
        return Some(ResolvedSessionLookup::local_query(lookup, origin));
    }
    if let Some((matched, origin)) = sessions.find_forward_wire_match_with_origin(key) {
        let lookup = SessionLookup {
            decision: matched.decision,
            metadata: matched.metadata,
        };
        if is_fabric_wire_placeholder(
            lookup.metadata.fabric_ingress,
            lookup.metadata.is_reverse,
            lookup.decision,
        ) && let Some(shared) =
            lookup_shared_forward_wire_match(shared_forward_wire_sessions, key)
        {
            return Some(ResolvedSessionLookup::shared(shared));
        }
        return Some(ResolvedSessionLookup::local(matched.key, lookup, origin));
    }
    lookup_shared_session(shared_sessions, key)
        .map(ResolvedSessionLookup::shared)
        .or_else(|| {
            lookup_shared_forward_wire_match(shared_forward_wire_sessions, key)
                .map(ResolvedSessionLookup::shared)
        })
}

pub(super) fn lookup_forward_nat_across_scopes(
    sessions: &SessionTable,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    reply_key: &SessionKey,
) -> Option<ForwardSessionMatch> {
    if let Some(local) = sessions.find_forward_nat_match(reply_key) {
        if is_fabric_wire_placeholder(
            local.metadata.fabric_ingress,
            local.metadata.is_reverse,
            local.decision,
        ) {
            return lookup_shared_forward_nat_match(shared_nat_sessions, reply_key).map(|entry| {
                ForwardSessionMatch {
                    key: entry.key,
                    decision: entry.decision,
                    metadata: entry.metadata,
                }
            });
        }
        return Some(local);
    }
    lookup_shared_forward_nat_match(shared_nat_sessions, reply_key).map(|entry| {
        ForwardSessionMatch {
            key: entry.key,
            decision: entry.decision,
            metadata: entry.metadata,
        }
    })
}

pub(super) fn build_reverse_session_from_forward_match(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    forward_match: ForwardSessionMatch,
    now_secs: u64,
    ha_startup_grace_until_secs: u64,
) -> SessionLookup {
    let requires_fabric_return = forward_match.metadata.fabric_ingress
        || forward_match.decision.resolution.disposition == ForwardingDisposition::FabricRedirect;
    let resolution = reverse_resolution_for_session(
        forwarding,
        ha_state,
        dynamic_neighbors,
        forward_match.key.src_ip,
        forward_match.metadata.ingress_zone,
        requires_fabric_return,
        now_secs,
        forward_match.decision.resolution.tunnel_endpoint_id != 0
            && now_secs <= ha_startup_grace_until_secs,
    );
    let metadata = SessionMetadata {
        ingress_zone: forward_match.metadata.egress_zone,
        egress_zone: forward_match.metadata.ingress_zone,
        // Reverse companions are owned by the RG that currently owns the
        // client-side egress resolution, not necessarily the RG that owned the
        // original forward session. This matters during failback when a second
        // RG comes up later and stale reverse entries must be repointed away
        // from prior FabricRedirect results.
        owner_rg_id: owner_rg_for_resolution(forwarding, resolution),
        fabric_ingress: forward_match.metadata.fabric_ingress,
        is_reverse: true,
        nat64_reverse: None,
    };
    let decision = SessionDecision {
        resolution: redirect_session_resolution_for_metadata(forwarding, resolution, &metadata),
        nat: forward_match.decision.nat.reverse(
            forward_match.key.src_ip,
            forward_match.key.dst_ip,
            forward_match.key.src_port,
            forward_match.key.dst_port,
        ),
    };
    SessionLookup { decision, metadata }
}

pub(super) fn synthesized_synced_reverse_entry(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    entry: &SyncedSessionEntry,
    now_secs: u64,
) -> Option<SyncedSessionEntry> {
    if entry.metadata.is_reverse {
        return None;
    }
    let reverse_key = reverse_session_key(&entry.key, entry.decision.nat);
    let reverse = build_reverse_session_from_forward_match(
        forwarding,
        ha_state,
        dynamic_neighbors,
        ForwardSessionMatch {
            key: entry.key.clone(),
            decision: entry.decision,
            metadata: entry.metadata.clone(),
        },
        now_secs,
        0,
    );
    let metadata = reverse.metadata;
    Some(SyncedSessionEntry {
        key: reverse_key,
        decision: reverse.decision,
        metadata,
        origin: SessionOrigin::SyncImport,
        protocol: entry.protocol,
        tcp_flags: entry.tcp_flags,
    })
}

pub(super) fn reverse_resolution_for_session(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    target_ip: IpAddr,
    ingress_zone: u16,
    fabric_ingress: bool,
    now_secs: u64,
    allow_unseeded_tunnel_local: bool,
) -> ForwardingResolution {
    let resolved =
        super::interface_nat_local_resolution(forwarding, target_ip).unwrap_or_else(|| {
            lookup_forwarding_resolution_with_dynamic(forwarding, dynamic_neighbors, target_ip)
        });
    let owner_rg_id = owner_rg_for_resolution(forwarding, resolved);
    if fabric_ingress
        && owner_rg_id > 0
        && !matches!(
            ha_state.get(&owner_rg_id),
            Some(group) if group.is_forwarding_active(now_secs)
        )
        && let Some(redirect) =
            super::forwarding::resolve_zone_encoded_fabric_redirect_by_id(forwarding, ingress_zone)
    {
        return redirect;
    }
    let enforced = enforce_ha_resolution_snapshot(forwarding, ha_state, now_secs, resolved);
    if allow_unseeded_tunnel_local
        && enforced.disposition == ForwardingDisposition::HAInactive
        && owner_rg_is_unseeded(forwarding, ha_state, resolved)
    {
        return resolved;
    }
    enforced
}

pub(super) fn install_reverse_session_from_forward_match(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    reverse_key: &SessionKey,
    forward_match: ForwardSessionMatch,
    now_ns: u64,
    now_secs: u64,
    ha_startup_grace_until_secs: u64,
    protocol: u8,
    tcp_flags: u8,
) -> SessionLookup {
    let reverse = build_reverse_session_from_forward_match(
        forwarding,
        ha_state,
        dynamic_neighbors,
        forward_match,
        now_secs,
        ha_startup_grace_until_secs,
    );
    if sessions.install_with_protocol_with_origin(
        reverse_key.clone(),
        reverse.decision,
        reverse.metadata.clone(),
        SessionOrigin::ReverseFlow,
        now_ns,
        protocol,
        tcp_flags,
    ) {
        // #1789: count failed reverse-install publishes (was `let _ =`).
        // No binding context in this shared-ops path — shared counter.
        if publish_live_session_entry(session_map_fd, reverse_key, reverse.decision.nat, true)
            .is_err()
        {
            SESSION_PUBLISH_ERRORS_SHARED.fetch_add(1, Ordering::Relaxed);
        }
        let reverse_entry = SyncedSessionEntry {
            key: reverse_key.clone(),
            decision: reverse.decision,
            metadata: reverse.metadata.clone(),
            origin: SessionOrigin::ReverseFlow,
            protocol,
            tcp_flags,
        };
        publish_shared_session(
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            &reverse_entry,
        );
        replicate_session_upsert(peer_worker_commands, &reverse_entry);
    }
    reverse
}

pub(super) fn publish_shared_session(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    entry: &SyncedSessionEntry,
) {
    if let Ok(mut sessions) = shared_sessions.lock() {
        let previous_owner_rg = sessions
            .insert(entry.key.clone(), entry.clone())
            .map(|existing| existing.metadata.owner_rg_id);
        update_owner_rg_index(
            &shared_owner_rg_indexes.sessions,
            &entry.key,
            previous_owner_rg,
            entry.metadata.owner_rg_id,
        );
    }
    if !entry.metadata.is_reverse
        && let Ok(mut sessions) = shared_nat_sessions.lock()
    {
        let reverse_wire = reverse_session_key(&entry.key, entry.decision.nat);
        let displaced = sessions.insert(reverse_wire.clone(), entry.clone());
        record_shared_nat_displacement(displaced.as_ref(), entry);
        let previous_owner_rg = displaced.map(|existing| existing.metadata.owner_rg_id);
        update_owner_rg_index(
            &shared_owner_rg_indexes.nat_sessions,
            &reverse_wire,
            previous_owner_rg,
            entry.metadata.owner_rg_id,
        );
        let reverse_canonical = reverse_canonical_key(&entry.key, entry.decision.nat);
        if reverse_canonical != reverse_wire {
            let displaced = sessions.insert(reverse_canonical.clone(), entry.clone());
            record_shared_nat_displacement(displaced.as_ref(), entry);
            let previous_owner_rg = displaced.map(|existing| existing.metadata.owner_rg_id);
            update_owner_rg_index(
                &shared_owner_rg_indexes.nat_sessions,
                &reverse_canonical,
                previous_owner_rg,
                entry.metadata.owner_rg_id,
            );
        }
    }
    if !entry.metadata.is_reverse
        && let Ok(mut sessions) = shared_forward_wire_sessions.lock()
    {
        let wire_key = forward_wire_key(&entry.key, entry.decision.nat);
        if wire_key != entry.key {
            let previous_owner_rg = sessions
                .insert(wire_key.clone(), entry.clone())
                .map(|existing| existing.metadata.owner_rg_id);
            update_owner_rg_index(
                &shared_owner_rg_indexes.forward_wire_sessions,
                &wire_key,
                previous_owner_rg,
                entry.metadata.owner_rg_id,
            );
        }
    }
}

pub(super) fn remove_shared_session(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    key: &SessionKey,
) {
    if let Ok(mut sessions) = shared_sessions.lock()
        && let Some(entry) = sessions.remove(key)
    {
        remove_owner_rg_index_entry(
            &shared_owner_rg_indexes.sessions,
            entry.metadata.owner_rg_id,
            key,
        );
        if !entry.metadata.is_reverse
            && let Ok(mut nat_sessions) = shared_nat_sessions.lock()
        {
            let reverse_wire = reverse_session_key(&entry.key, entry.decision.nat);
            if let Some(removed) = nat_sessions.remove(&reverse_wire) {
                remove_owner_rg_index_entry(
                    &shared_owner_rg_indexes.nat_sessions,
                    removed.metadata.owner_rg_id,
                    &reverse_wire,
                );
            }
            let reverse_canonical = reverse_canonical_key(&entry.key, entry.decision.nat);
            if reverse_canonical != reverse_wire
                && let Some(removed) = nat_sessions.remove(&reverse_canonical)
            {
                remove_owner_rg_index_entry(
                    &shared_owner_rg_indexes.nat_sessions,
                    removed.metadata.owner_rg_id,
                    &reverse_canonical,
                );
            }
            if let Ok(mut forward_wire_sessions) = shared_forward_wire_sessions.lock() {
                let wire_key = forward_wire_key(&entry.key, entry.decision.nat);
                if wire_key != entry.key
                    && let Some(removed) = forward_wire_sessions.remove(&wire_key)
                {
                    remove_owner_rg_index_entry(
                        &shared_owner_rg_indexes.forward_wire_sessions,
                        removed.metadata.owner_rg_id,
                        &wire_key,
                    );
                }
            }
        }
    }
}

pub(super) fn owner_rg_session_keys(
    index: &Arc<Mutex<OwnerRgSessionIndex>>,
    owner_rgs: &[i32],
) -> Vec<SessionKey> {
    let mut keys = FastSet::default();
    if let Ok(index) = index.lock() {
        for owner_rg_id in owner_rgs {
            if let Some(entries) = index.get(owner_rg_id) {
                keys.extend(entries.iter().cloned());
            }
        }
    }
    keys.into_iter().collect()
}

pub(super) fn owner_rg_session_keys_serialized(
    sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    index: &Arc<Mutex<OwnerRgSessionIndex>>,
    owner_rgs: &[i32],
) -> Vec<SessionKey> {
    let Ok(_sessions) = sessions.lock() else {
        return Vec::new();
    };
    owner_rg_session_keys(index, owner_rgs)
}

pub(super) fn refresh_reverse_prewarm_owner_rg_indexes(
    index: &Arc<Mutex<OwnerRgSessionIndex>>,
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    previous_entry: Option<&SyncedSessionEntry>,
    next_entry: Option<&SyncedSessionEntry>,
) {
    let previous_owner_rgs = previous_entry
        .map(|entry| reverse_prewarm_owner_rg_candidates(forwarding, dynamic_neighbors, entry));
    let next_owner_rgs = next_entry
        .map(|entry| reverse_prewarm_owner_rg_candidates(forwarding, dynamic_neighbors, entry));
    let Ok(mut index) = index.lock() else {
        return;
    };
    if let Some(previous_entry) = previous_entry {
        for owner_rg_id in previous_owner_rgs.unwrap_or_default() {
            remove_owner_rg_index_entry_locked(&mut index, owner_rg_id, &previous_entry.key);
        }
    }
    if let Some(next_entry) = next_entry {
        for owner_rg_id in next_owner_rgs.unwrap_or_default() {
            index
                .entry(owner_rg_id)
                .or_insert_with(FastSet::default)
                .insert(next_entry.key.clone());
        }
    }
}

fn reverse_prewarm_owner_rg_candidates(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    entry: &SyncedSessionEntry,
) -> FastSet<i32> {
    let mut owner_rgs = FastSet::default();
    if entry.metadata.is_reverse || !entry.origin.is_peer_synced() {
        return owner_rgs;
    }
    if entry.metadata.owner_rg_id > 0 {
        owner_rgs.insert(entry.metadata.owner_rg_id);
    }
    let reverse_resolution = super::interface_nat_local_resolution(forwarding, entry.key.src_ip)
        .unwrap_or_else(|| {
            lookup_forwarding_resolution_with_dynamic(
                forwarding,
                dynamic_neighbors,
                entry.key.src_ip,
            )
        });
    let reverse_owner_rg_id = owner_rg_for_resolution(forwarding, reverse_resolution);
    if reverse_owner_rg_id > 0 {
        owner_rgs.insert(reverse_owner_rg_id);
    }
    owner_rgs
}

fn update_owner_rg_index(
    index: &Arc<Mutex<OwnerRgSessionIndex>>,
    key: &SessionKey,
    previous_owner_rg: Option<i32>,
    owner_rg_id: i32,
) {
    if let Some(previous_owner_rg) = previous_owner_rg
        && previous_owner_rg != owner_rg_id
    {
        remove_owner_rg_index_entry(index, previous_owner_rg, key);
    }
    if owner_rg_id <= 0 {
        return;
    }
    if let Ok(mut index) = index.lock() {
        index
            .entry(owner_rg_id)
            .or_insert_with(FastSet::default)
            .insert(key.clone());
    }
}

fn remove_owner_rg_index_entry(
    index: &Arc<Mutex<OwnerRgSessionIndex>>,
    owner_rg_id: i32,
    key: &SessionKey,
) {
    if owner_rg_id <= 0 {
        return;
    }
    if let Ok(mut index) = index.lock() {
        remove_owner_rg_index_entry_locked(&mut index, owner_rg_id, key);
    }
}

fn remove_owner_rg_index_entry_locked(
    index: &mut OwnerRgSessionIndex,
    owner_rg_id: i32,
    key: &SessionKey,
) {
    if let Some(keys) = index.get_mut(&owner_rg_id) {
        keys.remove(key);
        if keys.is_empty() {
            index.remove(&owner_rg_id);
        }
    }
}
