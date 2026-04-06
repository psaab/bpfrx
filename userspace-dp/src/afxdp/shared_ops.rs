use super::*;

pub(super) fn demote_shared_owner_rgs(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    owner_rgs: &[i32],
) {
    if owner_rgs.is_empty() {
        return;
    }
    if let Ok(mut sessions) = shared_sessions.lock() {
        for key in owner_rg_session_keys(&shared_owner_rg_indexes.sessions, owner_rgs) {
            if let Some(entry) = sessions.get_mut(&key) {
                entry.origin = SessionOrigin::SyncImport;
            }
        }
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
    replica.origin = SessionOrigin::SyncImport;
    replica
}

/// Pre-warm reverse companions in shared session maps at RG activation.
///
/// With deterministic reverse companions (#310), the Go sync path already
/// pre-installs reverse entries via UpsertSynced. This function still runs
/// at activation to re-resolve egress with local forwarding state (the
/// pre-installed entries carry the peer's interface indices/MACs).
pub(super) fn prewarm_reverse_synced_sessions_for_owner_rgs(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    session_map_fd: c_int,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    owner_rgs: &[i32],
    now_secs: u64,
) {
    if owner_rgs.is_empty() {
        return;
    }
    let owner_rg_set: std::collections::BTreeSet<i32> = owner_rgs.iter().copied().collect();
    let candidate_keys = owner_rg_session_keys_serialized(
        shared_sessions,
        &shared_owner_rg_indexes.reverse_prewarm_sessions,
        owner_rgs,
    );
    let (forward_entries, reverse_entries) = shared_sessions
        .lock()
        .map(|sessions| {
            let mut forward_entries = Vec::new();
            let mut reverse_entries = Vec::new();
            for key in candidate_keys {
                let Some(entry) = sessions.get(&key) else {
                    continue;
                };
                if entry.metadata.is_reverse || !entry.origin.is_peer_synced() {
                    continue;
                }
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
                    reverse_entries.push(reverse);
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
        if publish_session_map_entry_for_session(
            session_map_fd,
            &forward.key,
            forward.decision,
            &forward.metadata,
        )
        .is_err()
        {
            fwd_publish_errors += 1;
        }
        for commands in worker_commands {
            if let Ok(mut pending) = commands.lock() {
                pending.push_back(WorkerCommand::UpsertSynced(forward.clone()));
            }
        }
    }
    if fwd_publish_errors > 0 {
        eprintln!(
            "bpfrx-ha: prewarm forward BPF publish: {} errors out of {} entries",
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
        let _ = publish_session_map_entry_for_session(
            session_map_fd,
            &reverse.key,
            reverse.decision,
            &reverse.metadata,
        );
        for commands in worker_commands {
            if let Ok(mut pending) = commands.lock() {
                pending.push_back(WorkerCommand::UpsertSynced(reverse.clone()));
            }
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
        }
    }
    if errors > 0 {
        eprintln!(
            "bpfrx-ha: republish_bpf_session_entries: {} errors out of {} attempted",
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
    pub(super) decision: SessionDecision,
    pub(super) metadata: SessionMetadata,
    pub(super) created: bool,
}

pub(super) fn lookup_session_across_scopes(
    sessions: &mut SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    key: &SessionKey,
    now_ns: u64,
    tcp_flags: u8,
) -> Option<ResolvedSessionLookup> {
    sessions
        .lookup_with_origin(key, now_ns, tcp_flags)
        .map(|(lookup, origin)| ResolvedSessionLookup::local_query(lookup, origin))
        .or_else(|| {
            sessions
                .find_forward_wire_match_with_origin(key)
                .map(|(matched, origin)| {
                    ResolvedSessionLookup::local(
                        matched.key,
                        SessionLookup {
                            decision: matched.decision,
                            metadata: matched.metadata,
                        },
                        origin,
                    )
                })
        })
        .or_else(|| lookup_shared_session(shared_sessions, key).map(ResolvedSessionLookup::shared))
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
    sessions.find_forward_nat_match(reply_key).or_else(|| {
        lookup_shared_forward_nat_match(shared_nat_sessions, reply_key).map(|entry| {
            ForwardSessionMatch {
                key: entry.key,
                decision: entry.decision,
                metadata: entry.metadata,
            }
        })
    })
}

pub(super) fn build_reverse_session_from_forward_match(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    forward_match: ForwardSessionMatch,
    now_secs: u64,
    ha_startup_grace_until_secs: u64,
) -> SessionLookup {
    let resolution = reverse_resolution_for_session(
        forwarding,
        ha_state,
        dynamic_neighbors,
        forward_match.key.src_ip,
        forward_match.metadata.ingress_zone.as_ref(),
        forward_match.metadata.fabric_ingress,
        now_secs,
        forward_match.decision.resolution.tunnel_endpoint_id != 0
            && now_secs <= ha_startup_grace_until_secs,
    );
    let metadata = SessionMetadata {
        ingress_zone: forward_match.metadata.egress_zone.clone(),
        egress_zone: forward_match.metadata.ingress_zone.clone(),
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
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
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
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    target_ip: IpAddr,
    ingress_zone: &str,
    fabric_ingress: bool,
    now_secs: u64,
    allow_unseeded_tunnel_local: bool,
) -> ForwardingResolution {
    if let Some(local) = super::interface_nat_local_resolution(forwarding, target_ip) {
        return local;
    }
    let resolved =
        lookup_forwarding_resolution_with_dynamic(forwarding, dynamic_neighbors, target_ip);
    if fabric_ingress
        && owner_rg_for_resolution(forwarding, resolved) > 0
        && !matches!(
            ha_state.get(&owner_rg_for_resolution(forwarding, resolved)),
            Some(group) if group.is_forwarding_active(now_secs)
        )
        && let Some(redirect) = resolve_zone_encoded_fabric_redirect(forwarding, ingress_zone)
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
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
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
        let _ = publish_live_session_entry(session_map_fd, reverse_key, reverse.decision.nat, true);
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
        let previous_owner_rg = sessions
            .insert(reverse_wire.clone(), entry.clone())
            .map(|existing| existing.metadata.owner_rg_id);
        update_owner_rg_index(
            &shared_owner_rg_indexes.nat_sessions,
            &reverse_wire,
            previous_owner_rg,
            entry.metadata.owner_rg_id,
        );
        let reverse_canonical = reverse_canonical_key(&entry.key, entry.decision.nat);
        if reverse_canonical != reverse_wire {
            let previous_owner_rg = sessions
                .insert(reverse_canonical.clone(), entry.clone())
                .map(|existing| existing.metadata.owner_rg_id);
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
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
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
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
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
