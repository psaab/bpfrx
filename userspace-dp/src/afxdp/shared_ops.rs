use super::*;

pub(super) fn demote_shared_owner_rgs(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    owner_rgs: &[i32],
) {
    if owner_rgs.is_empty() {
        return;
    }
    let owner_rg_set: std::collections::BTreeSet<i32> = owner_rgs.iter().copied().collect();
    let should_demote =
        |entry: &SyncedSessionEntry| owner_rg_set.contains(&entry.metadata.owner_rg_id);
    if let Ok(mut sessions) = shared_sessions.lock() {
        for entry in sessions.values_mut() {
            if should_demote(entry) {
                entry.origin = SessionOrigin::SyncImport;
            }
        }
    }
    if let Ok(mut sessions) = shared_nat_sessions.lock() {
        for entry in sessions.values_mut() {
            if should_demote(entry) {
                entry.origin = SessionOrigin::SyncImport;
            }
        }
    }
    if let Ok(mut sessions) = shared_forward_wire_sessions.lock() {
        for entry in sessions.values_mut() {
            if should_demote(entry) {
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
    // Reverse companions depend on the current HA state of the client-side
    // egress RG, not only on the forward session's owner RG. When a second RG
    // becomes active during failback (for example, LAN after WAN/tunnel), a
    // previously synthesized reverse session can flip from FabricRedirect back
    // to local ForwardCandidate. Recompute all synced forward entries on RG
    // activation so stale reverse companions are refreshed against the new HA
    // snapshot instead of staying pinned to the earlier inactive result.
    let reverse_entries = shared_sessions
        .lock()
        .map(|sessions| {
            let mut reverse_entries = Vec::new();
            sessions
                .values()
                .filter(|entry| !entry.metadata.is_reverse && entry.origin.is_peer_synced())
                .for_each(|entry| {
                    let Some(reverse) = synthesized_synced_reverse_entry(
                        forwarding,
                        ha_state,
                        dynamic_neighbors,
                        entry,
                        now_secs,
                    ) else {
                        return;
                    };
                    if owner_rg_set.contains(&entry.metadata.owner_rg_id)
                        || owner_rg_set.contains(&reverse.metadata.owner_rg_id)
                    {
                        reverse_entries.push(reverse);
                    }
                });
            reverse_entries
        })
        .unwrap_or_default();
    if reverse_entries.is_empty() {
        return;
    }
    for reverse in reverse_entries {
        publish_shared_session(
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
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
}

impl ResolvedSessionLookup {
    pub(super) fn local_query(lookup: SessionLookup) -> Self {
        Self {
            key: ResolvedSessionKey::QueryKey,
            lookup,
            shared_entry: None,
        }
    }

    pub(super) fn local(key: SessionKey, lookup: SessionLookup) -> Self {
        Self {
            key: ResolvedSessionKey::Canonical(key),
            lookup,
            shared_entry: None,
        }
    }

    pub(super) fn shared(entry: SyncedSessionEntry) -> Self {
        Self {
            key: ResolvedSessionKey::Canonical(entry.key.clone()),
            lookup: SessionLookup {
                decision: entry.decision,
                metadata: entry.metadata.clone(),
            },
            shared_entry: Some(entry),
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
        .lookup(key, now_ns, tcp_flags)
        .map(ResolvedSessionLookup::local_query)
        .or_else(|| {
            sessions.find_forward_wire_match(key).map(|matched| {
                ResolvedSessionLookup::local(
                    matched.key,
                    SessionLookup {
                        decision: matched.decision,
                        metadata: matched.metadata,
                    },
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
    entry: &SyncedSessionEntry,
) {
    if let Ok(mut sessions) = shared_sessions.lock() {
        sessions.insert(entry.key.clone(), entry.clone());
    }
    if !entry.metadata.is_reverse
        && let Ok(mut sessions) = shared_nat_sessions.lock()
    {
        let reverse_wire = reverse_session_key(&entry.key, entry.decision.nat);
        sessions.insert(reverse_wire.clone(), entry.clone());
        let reverse_canonical = reverse_canonical_key(&entry.key, entry.decision.nat);
        if reverse_canonical != reverse_wire {
            sessions.insert(reverse_canonical, entry.clone());
        }
    }
    if !entry.metadata.is_reverse
        && let Ok(mut sessions) = shared_forward_wire_sessions.lock()
    {
        let wire_key = forward_wire_key(&entry.key, entry.decision.nat);
        if wire_key != entry.key {
            sessions.insert(wire_key, entry.clone());
        }
    }
}

pub(super) fn remove_shared_session(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    key: &SessionKey,
) {
    if let Ok(mut sessions) = shared_sessions.lock()
        && let Some(entry) = sessions.remove(key)
        && !entry.metadata.is_reverse
        && let Ok(mut nat_sessions) = shared_nat_sessions.lock()
    {
        let reverse_wire = reverse_session_key(&entry.key, entry.decision.nat);
        nat_sessions.remove(&reverse_wire);
        let reverse_canonical = reverse_canonical_key(&entry.key, entry.decision.nat);
        if reverse_canonical != reverse_wire {
            nat_sessions.remove(&reverse_canonical);
        }
        if let Ok(mut forward_wire_sessions) = shared_forward_wire_sessions.lock() {
            let wire_key = forward_wire_key(&entry.key, entry.decision.nat);
            if wire_key != entry.key {
                forward_wire_sessions.remove(&wire_key);
            }
        }
    }
}
