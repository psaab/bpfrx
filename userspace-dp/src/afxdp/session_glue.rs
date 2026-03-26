use super::*;

pub(super) fn reverse_session_key(key: &SessionKey, nat: NatDecision) -> SessionKey {
    let (src_port, dst_port) = if matches!(key.protocol, PROTO_ICMP | PROTO_ICMPV6) {
        (key.src_port, key.dst_port)
    } else {
        (
            nat.rewrite_dst_port.unwrap_or(key.dst_port),
            nat.rewrite_src_port.unwrap_or(key.src_port),
        )
    };
    let wire_src = nat.rewrite_dst.unwrap_or(key.dst_ip);
    let wire_dst = nat.rewrite_src.unwrap_or(key.src_ip);
    let (addr_family, protocol) = if nat.nat64 {
        let af = match wire_src {
            IpAddr::V4(_) => libc::AF_INET as u8,
            IpAddr::V6(_) => libc::AF_INET6 as u8,
        };
        let proto = if af == libc::AF_INET as u8 && key.protocol == PROTO_ICMPV6 {
            PROTO_ICMP
        } else if af == libc::AF_INET6 as u8 && key.protocol == PROTO_ICMP {
            PROTO_ICMPV6
        } else {
            key.protocol
        };
        (af, proto)
    } else {
        (key.addr_family, key.protocol)
    };
    SessionKey {
        addr_family,
        protocol,
        src_ip: wire_src,
        dst_ip: wire_dst,
        src_port,
        dst_port,
    }
}

pub(super) fn resolution_target_for_session(
    flow: &SessionFlow,
    decision: SessionDecision,
) -> IpAddr {
    decision.nat.rewrite_dst.unwrap_or(flow.dst_ip)
}

pub(super) fn cached_session_resolution(
    forwarding: &ForwardingState,
    cached: ForwardingResolution,
) -> Option<ForwardingResolution> {
    if cached.egress_ifindex <= 0 || cached.neighbor_mac.is_none() {
        return None;
    }
    let mut fallback = cached;
    fallback.disposition = ForwardingDisposition::ForwardCandidate;
    if fallback.tx_ifindex <= 0 {
        fallback.tx_ifindex = resolve_tx_binding_ifindex(forwarding, fallback.egress_ifindex);
    }
    if let Some(egress) = forwarding.egress.get(&fallback.egress_ifindex) {
        if fallback.src_mac.is_none() {
            fallback.src_mac = Some(egress.src_mac);
        }
        if fallback.tx_vlan_id == 0 {
            fallback.tx_vlan_id = egress.vlan_id;
        }
    }
    Some(fallback)
}

pub(super) fn populate_egress_resolution(
    state: &ForwardingState,
    egress_ifindex: i32,
    resolution: &mut ForwardingResolution,
) {
    if egress_ifindex <= 0 {
        return;
    }
    if let Some(egress) = state.egress.get(&egress_ifindex) {
        resolution.tx_ifindex = if egress.bind_ifindex > 0 {
            egress.bind_ifindex
        } else {
            egress_ifindex
        };
        resolution.src_mac = Some(egress.src_mac);
        resolution.tx_vlan_id = egress.vlan_id;
    } else if resolution.tx_ifindex <= 0 {
        resolution.tx_ifindex = egress_ifindex;
    }
}

pub(super) fn lookup_forwarding_resolution_for_session(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    flow: &SessionFlow,
    decision: SessionDecision,
) -> ForwardingResolution {
    if decision.resolution.disposition == ForwardingDisposition::LocalDelivery {
        return decision.resolution;
    }
    if decision.resolution.tunnel_endpoint_id != 0 {
        let resolved = super::resolve_tunnel_forwarding_resolution(
            forwarding,
            Some(dynamic_neighbors),
            decision.resolution.tunnel_endpoint_id,
            0,
        );
        return match resolved.disposition {
            ForwardingDisposition::NoRoute | ForwardingDisposition::MissingNeighbor => {
                cached_session_resolution(forwarding, decision.resolution).unwrap_or(resolved)
            }
            _ => resolved,
        };
    }
    if let Some(cached) = cached_session_resolution(forwarding, decision.resolution) {
        return cached;
    }
    let target = resolution_target_for_session(flow, decision);
    if let Some(local) = super::interface_nat_local_resolution(forwarding, target) {
        return local;
    }
    let resolved = lookup_forwarding_resolution_with_dynamic(forwarding, dynamic_neighbors, target);
    match resolved.disposition {
        ForwardingDisposition::NoRoute | ForwardingDisposition::MissingNeighbor => {
            cached_session_resolution(forwarding, decision.resolution).unwrap_or(resolved)
        }
        _ => resolved,
    }
}

pub(super) fn owner_rg_is_locally_active(
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    owner_rg_id: i32,
    now_secs: u64,
) -> bool {
    owner_rg_id > 0
        && matches!(
            ha_state.get(&owner_rg_id),
            Some(group)
                if group.active
                    && group.watchdog_timestamp != 0
                    && now_secs >= group.watchdog_timestamp
                    && now_secs.saturating_sub(group.watchdog_timestamp)
                        <= HA_WATCHDOG_STALE_AFTER_SECS
        )
}

fn owner_rg_is_unseeded(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    resolution: ForwardingResolution,
) -> bool {
    let owner_rg_id = owner_rg_for_resolution(forwarding, resolution);
    owner_rg_id > 0
        && matches!(
            ha_state.get(&owner_rg_id),
            None | Some(HAGroupRuntime {
                active: false,
                watchdog_timestamp: 0,
            })
        )
}

fn should_bypass_unseeded_tunnel_ha(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    resolution: ForwardingResolution,
    ingress_ifindex: i32,
    ha_startup_grace_until_secs: u64,
) -> bool {
    resolution.disposition == ForwardingDisposition::ForwardCandidate
        && now_secs <= ha_startup_grace_until_secs
        && forwarding
            .tunnel_endpoint_by_ifindex
            .contains_key(&ingress_ifindex)
        && owner_rg_is_unseeded(forwarding, ha_state, resolution)
}

pub(super) fn apply_worker_commands(
    commands: &Arc<Mutex<VecDeque<WorkerCommand>>>,
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
) {
    // Hot path: try_lock avoids blocking on the mutex when another thread
    // holds it (rare) and avoids the cost of lock+unlock on empty queues
    // when there's nothing to do (common case during steady-state forwarding).
    let pending = match commands.try_lock() {
        Ok(mut pending) => {
            if pending.is_empty() {
                return;
            }
            core::mem::take(&mut *pending)
        }
        Err(_) => return,
    };
    let now_ns = monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    for cmd in pending {
        match cmd {
            WorkerCommand::DemoteOwnerRG(owner_rg_id) => {
                sessions.demote_owner_rg(owner_rg_id);
            }
            WorkerCommand::RefreshOwnerRGs(owner_rgs) => {
                refresh_live_reverse_sessions_for_owner_rgs(
                    sessions,
                    session_map_fd,
                    forwarding,
                    ha_state,
                    dynamic_neighbors,
                    &owner_rgs,
                    now_ns,
                    now_secs,
                );
            }
            WorkerCommand::UpsertSynced(entry) => {
                let key = entry.key.clone();
                let metadata = entry.metadata.clone();
                let allow_replace_local =
                    !owner_rg_is_locally_active(ha_state, entry.metadata.owner_rg_id, now_secs);
                if sessions.upsert_synced(
                    entry.key,
                    entry.decision,
                    entry.metadata,
                    now_ns,
                    entry.protocol,
                    entry.tcp_flags,
                    allow_replace_local,
                ) {
                    let _ = publish_session_map_entry_for_session(
                        session_map_fd,
                        &key,
                        entry.decision,
                        &metadata,
                    );
                }
            }
            WorkerCommand::UpsertLocal(entry) => {
                sessions.install_with_protocol(
                    entry.key,
                    entry.decision,
                    entry.metadata,
                    now_ns,
                    entry.protocol,
                    entry.tcp_flags,
                );
            }
            WorkerCommand::DeleteSynced(key) => {
                let delete_alias = sessions.lookup(&key, now_ns, 0);
                sessions.delete(&key);
                if let Some(lookup) = delete_alias {
                    delete_session_map_entry_for_removed_session(
                        session_map_fd,
                        &key,
                        lookup.decision,
                        &lookup.metadata,
                    );
                } else {
                    delete_live_session_key(session_map_fd, &key);
                }
            }
        }
    }
}

pub(super) fn replicate_session_upsert(
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    entry: &SyncedSessionEntry,
) {
    let replica = synced_replica_entry(entry);
    for commands in worker_commands {
        if let Ok(mut pending) = commands.lock() {
            pending.push_back(WorkerCommand::UpsertSynced(replica.clone()));
        }
    }
}

pub(super) fn replicate_session_delete(
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    key: &SessionKey,
) {
    for commands in worker_commands {
        if let Ok(mut pending) = commands.lock() {
            pending.push_back(WorkerCommand::DeleteSynced(key.clone()));
        }
    }
}

pub(super) fn demote_shared_owner_rgs(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    owner_rgs: &[i32],
) {
    if owner_rgs.is_empty() {
        return;
    }
    let should_demote =
        |entry: &SyncedSessionEntry| owner_rgs.contains(&entry.metadata.owner_rg_id);
    if let Ok(mut sessions) = shared_sessions.lock() {
        for entry in sessions.values_mut() {
            if should_demote(entry) {
                entry.metadata.synced = true;
            }
        }
    }
    if let Ok(mut sessions) = shared_nat_sessions.lock() {
        for entry in sessions.values_mut() {
            if should_demote(entry) {
                entry.metadata.synced = true;
            }
        }
    }
    if let Ok(mut sessions) = shared_forward_wire_sessions.lock() {
        for entry in sessions.values_mut() {
            if should_demote(entry) {
                entry.metadata.synced = true;
            }
        }
    }
}

pub(super) fn synced_replica_entry(entry: &SyncedSessionEntry) -> SyncedSessionEntry {
    let mut replica = entry.clone();
    replica.metadata.synced = true;
    replica
}

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
    // Reverse companions depend on the current HA state of the client-side
    // egress RG, not only on the forward session's owner RG. When a second RG
    // becomes active during failback (for example, LAN after WAN/tunnel), a
    // previously synthesized reverse session can flip from FabricRedirect back
    // to local ForwardCandidate. Recompute all synced forward entries on RG
    // activation so stale reverse companions are refreshed against the new HA
    // snapshot instead of staying pinned to the earlier inactive result.
    let forward_entries = shared_sessions
        .lock()
        .map(|sessions| {
            sessions
                .values()
                .filter(|entry| !entry.metadata.is_reverse && entry.metadata.synced)
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if forward_entries.is_empty() {
        return;
    }
    for entry in forward_entries {
        let Some(reverse) = synthesized_synced_reverse_entry(
            forwarding,
            ha_state,
            dynamic_neighbors,
            &entry,
            now_secs,
        ) else {
            continue;
        };
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

pub(super) fn refresh_live_reverse_sessions_for_owner_rgs(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    owner_rgs: &[i32],
    now_ns: u64,
    now_secs: u64,
) {
    if owner_rgs.is_empty() {
        return;
    }
    let candidates = {
        let mut out = Vec::new();
        sessions.iter(|key, decision, metadata| {
            if metadata.synced || !metadata.is_reverse {
                return;
            }
            out.push((key.clone(), decision, metadata.clone()));
        });
        out
    };
    for (key, decision, metadata) in candidates {
        let flow = SessionFlow {
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            forward_key: key.clone(),
        };
        let looked_up = lookup_forwarding_resolution_for_session(
            forwarding,
            dynamic_neighbors,
            &flow,
            decision,
        );
        let refreshed_resolution =
            enforce_session_ha_resolution(forwarding, ha_state, now_secs, looked_up, 0, 0);
        let refreshed_owner_rg = owner_rg_for_resolution(forwarding, refreshed_resolution);
        if !owner_rgs.contains(&refreshed_owner_rg)
            && !owner_rgs.contains(&metadata.owner_rg_id)
            && refreshed_resolution == decision.resolution
            && refreshed_owner_rg == metadata.owner_rg_id
        {
            continue;
        }
        let refreshed_decision = SessionDecision {
            resolution: refreshed_resolution,
            ..decision
        };
        let refreshed_metadata = SessionMetadata {
            owner_rg_id: refreshed_owner_rg,
            ..metadata
        };
        if sessions.refresh_local(
            &key,
            refreshed_decision,
            refreshed_metadata.clone(),
            now_ns,
            0,
        ) {
            let _ = publish_session_map_entry_for_session(
                session_map_fd,
                &key,
                refreshed_decision,
                &refreshed_metadata,
            );
        }
    }
}

pub(super) fn should_teardown_tcp_rst(_meta: UserspaceDpMeta, _flow: Option<&SessionFlow>) -> bool {
    // Do not immediately delete live sessions on an observed TCP RST.
    //
    // On the current HA userspace dataplane, stray or misclassified reply-side
    // RSTs can appear while the real flow is still active. Immediate teardown
    // removes the pinned live-session keys from USERSPACE_SESSIONS, which then
    // causes userspace-xdp to stop redirecting valid reply traffic and the
    // kernel to emit follow-on RSTs that collapse the connection entirely.
    //
    // The session table already marks TCP entries as closing when FIN/RST is
    // seen and ages them on the shorter TCP_CLOSING timeout. Rely on that
    // path for now until RST provenance is made trustworthy again.
    false
}

pub(super) fn teardown_tcp_rst_flow(
    left: &mut [BindingWorker],
    current: &mut BindingWorker,
    right: &mut [BindingWorker],
    sessions: &mut SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    forward_key: &SessionKey,
    nat: NatDecision,
    pending_forwards: &mut Vec<PendingForwardRequest>,
) {
    let reverse_key = reverse_session_key(forward_key, nat);
    sessions.delete(forward_key);
    sessions.delete(&reverse_key);
    delete_live_session_entry(current.session_map_fd, forward_key, nat, false);
    delete_live_session_entry(current.session_map_fd, &reverse_key, nat, true);
    remove_shared_session(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        forward_key,
    );
    remove_shared_session(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        &reverse_key,
    );
    replicate_session_delete(peer_worker_commands, forward_key);
    replicate_session_delete(peer_worker_commands, &reverse_key);
    cancel_pending_forwards(current, pending_forwards, forward_key, &reverse_key);
    cancel_queued_flow(left, current, right, forward_key, &reverse_key);
}

pub(super) fn cancel_queued_flow(
    left: &mut [BindingWorker],
    current: &mut BindingWorker,
    right: &mut [BindingWorker],
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
) {
    for binding in left.iter_mut() {
        cancel_queued_flow_on_binding(binding, forward_key, reverse_key);
    }
    cancel_queued_flow_on_binding(current, forward_key, reverse_key);
    for binding in right.iter_mut() {
        cancel_queued_flow_on_binding(binding, forward_key, reverse_key);
    }
}

pub(super) fn cancel_queued_flow_on_binding(
    binding: &mut BindingWorker,
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
) {
    let mut kept_local = VecDeque::with_capacity(binding.pending_tx_local.len());
    while let Some(req) = binding.pending_tx_local.pop_front() {
        if tx_request_matches_flow(&req, forward_key, reverse_key) {
            continue;
        }
        kept_local.push_back(req);
    }
    binding.pending_tx_local = kept_local;

    let mut kept_prepared = VecDeque::with_capacity(binding.pending_tx_prepared.len());
    while let Some(req) = binding.pending_tx_prepared.pop_front() {
        if prepared_request_matches_flow(&req, forward_key, reverse_key) {
            recycle_cancelled_prepared(binding, &req);
            continue;
        }
        kept_prepared.push_back(req);
    }
    binding.pending_tx_prepared = kept_prepared;

    if let Ok(mut pending) = binding.live.pending_tx.lock() {
        let mut kept_shared = VecDeque::with_capacity(pending.len());
        while let Some(req) = pending.pop_front() {
            if tx_request_matches_flow(&req, forward_key, reverse_key) {
                continue;
            }
            kept_shared.push_back(req);
        }
        binding
            .live
            .pending_tx_len
            .store(kept_shared.len() as u32, Ordering::Relaxed);
        *pending = kept_shared;
    }

    update_binding_debug_state(binding);
}

pub(super) fn cancel_pending_forwards(
    binding: &mut BindingWorker,
    pending_forwards: &mut Vec<PendingForwardRequest>,
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
) {
    let mut kept = Vec::with_capacity(pending_forwards.len());
    for req in pending_forwards.drain(..) {
        if pending_forward_matches_flow(&req, forward_key, reverse_key) {
            binding.pending_fill_frames.push_back(req.source_offset);
            continue;
        }
        kept.push(req);
    }
    *pending_forwards = kept;
}

pub(super) fn recycle_cancelled_prepared(binding: &mut BindingWorker, req: &PreparedTxRequest) {
    match req.recycle {
        PreparedTxRecycle::FreeTxFrame => binding.free_tx_frames.push_back(req.offset),
        PreparedTxRecycle::FillOnSlot(slot) if slot == binding.slot => {
            binding.pending_fill_frames.push_back(req.offset);
        }
        PreparedTxRecycle::FillOnSlot(_) => binding.free_tx_frames.push_back(req.offset),
    }
}

pub(super) fn tx_request_matches_flow(
    req: &TxRequest,
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
) -> bool {
    matches!(
        req.flow_key.as_ref(),
        Some(key) if key == forward_key || key == reverse_key
    )
}

pub(super) fn prepared_request_matches_flow(
    req: &PreparedTxRequest,
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
) -> bool {
    matches!(
        req.flow_key.as_ref(),
        Some(key) if key == forward_key || key == reverse_key
    )
}

pub(super) fn pending_forward_matches_flow(
    req: &PendingForwardRequest,
    forward_key: &SessionKey,
    reverse_key: &SessionKey,
) -> bool {
    matches!(
        req.flow_key.as_ref(),
        Some(key) if key == forward_key || key == reverse_key
    )
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
    fn as_ref<'a>(&'a self, query_key: &'a SessionKey) -> &'a SessionKey {
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
    fn local_query(lookup: SessionLookup) -> Self {
        Self {
            key: ResolvedSessionKey::QueryKey,
            lookup,
            shared_entry: None,
        }
    }

    fn local(key: SessionKey, lookup: SessionLookup) -> Self {
        Self {
            key: ResolvedSessionKey::Canonical(key),
            lookup,
            shared_entry: None,
        }
    }

    fn shared(entry: SyncedSessionEntry) -> Self {
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

fn materialize_shared_session_hit(
    sessions: &mut SessionTable,
    resolved: &mut ResolvedSessionLookup,
    now_ns: u64,
    tcp_flags: u8,
) -> SessionLookup {
    if let Some(shared) = resolved.shared_entry.take() {
        let replica = synced_replica_entry(&shared);
        sessions.upsert_synced(
            replica.key.clone(),
            replica.decision,
            replica.metadata.clone(),
            now_ns,
            replica.protocol,
            tcp_flags,
            false,
        );
        return SessionLookup {
            decision: replica.decision,
            metadata: replica.metadata,
        };
    }
    resolved.lookup.clone()
}

fn build_reverse_session_from_forward_match(
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
    let decision = SessionDecision {
        resolution,
        nat: forward_match.decision.nat.reverse(
            forward_match.key.src_ip,
            forward_match.key.dst_ip,
            forward_match.key.src_port,
            forward_match.key.dst_port,
        ),
    };
    let metadata = SessionMetadata {
        ingress_zone: forward_match.metadata.egress_zone.clone(),
        egress_zone: forward_match.metadata.ingress_zone.clone(),
        // Reverse companions are owned by the RG that currently owns the
        // client-side egress resolution, not necessarily the RG that owned the
        // original forward session. This matters during failback when a second
        // RG comes up later and stale reverse entries must be repointed away
        // from prior FabricRedirect results.
        owner_rg_id: owner_rg_for_resolution(forwarding, decision.resolution),
        fabric_ingress: forward_match.metadata.fabric_ingress,
        is_reverse: true,
        synced: false,
        nat64_reverse: None,
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
    let mut metadata = reverse.metadata;
    metadata.synced = true;
    Some(SyncedSessionEntry {
        key: reverse_key,
        decision: reverse.decision,
        metadata,
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
            Some(group)
                if group.active
                    && group.watchdog_timestamp != 0
                    && now_secs >= group.watchdog_timestamp
                    && now_secs.saturating_sub(group.watchdog_timestamp)
                        <= HA_WATCHDOG_STALE_AFTER_SECS
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

fn install_reverse_session_from_forward_match(
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
    if sessions.install_with_protocol(
        reverse_key.clone(),
        reverse.decision,
        reverse.metadata.clone(),
        now_ns,
        protocol,
        tcp_flags,
    ) {
        let _ = publish_live_session_entry(session_map_fd, reverse_key, reverse.decision.nat, true);
        let reverse_entry = SyncedSessionEntry {
            key: reverse_key.clone(),
            decision: reverse.decision,
            metadata: reverse.metadata.clone(),
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

fn maybe_promote_synced_session(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    forwarding: &ForwardingState,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: SessionMetadata,
    ingress_ifindex: i32,
    now_ns: u64,
    protocol: u8,
    tcp_flags: u8,
) -> SessionMetadata {
    if !metadata.synced
        || decision.resolution.disposition != ForwardingDisposition::ForwardCandidate
    {
        return metadata;
    }

    let mut promoted = metadata;
    promoted.synced = false;
    if promoted.owner_rg_id <= 0 {
        promoted.owner_rg_id = owner_rg_for_resolution(forwarding, decision.resolution);
    }
    if ingress_is_fabric(forwarding, ingress_ifindex) {
        promoted.fabric_ingress = true;
    }
    if sessions.promote_synced(key, decision, promoted.clone(), now_ns, protocol, tcp_flags) {
        let _ = publish_session_map_entry_for_session(session_map_fd, key, decision, &promoted);
        let promoted_entry = SyncedSessionEntry {
            key: key.clone(),
            decision,
            metadata: promoted.clone(),
            protocol,
            tcp_flags,
        };
        publish_shared_session(
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            &promoted_entry,
        );
        replicate_session_upsert(peer_worker_commands, &promoted_entry);
    }
    promoted
}

pub(super) fn resolve_flow_session_decision(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    flow: &SessionFlow,
    now_ns: u64,
    now_secs: u64,
    protocol: u8,
    tcp_flags: u8,
    ingress_ifindex: i32,
    ha_startup_grace_until_secs: u64,
) -> Option<ResolvedFlowSessionDecision> {
    if let Some(mut hit) = lookup_session_across_scopes(
        sessions,
        shared_sessions,
        shared_forward_wire_sessions,
        &flow.forward_key,
        now_ns,
        tcp_flags,
    ) {
        let resolved = materialize_shared_session_hit(sessions, &mut hit, now_ns, tcp_flags);
        let resolved_key = hit.key.as_ref(&flow.forward_key);
        let mut decision = resolved.decision;
        let looked_up_resolution =
            lookup_forwarding_resolution_for_session(forwarding, dynamic_neighbors, flow, decision);
        let enforced_resolution = enforce_session_ha_resolution(
            forwarding,
            ha_state,
            now_secs,
            looked_up_resolution,
            ingress_ifindex,
            ha_startup_grace_until_secs,
        );
        decision.resolution = redirect_session_via_fabric_if_needed(
            forwarding,
            enforced_resolution,
            ingress_ifindex,
            resolved.metadata.ingress_zone.as_ref(),
        );
        let metadata = maybe_promote_synced_session(
            sessions,
            session_map_fd,
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            peer_worker_commands,
            forwarding,
            resolved_key,
            decision,
            resolved.metadata,
            ingress_ifindex,
            now_ns,
            protocol,
            tcp_flags,
        );
        return Some(ResolvedFlowSessionDecision {
            decision,
            metadata,
            created: false,
        });
    }

    let forward_match =
        lookup_forward_nat_across_scopes(sessions, shared_nat_sessions, &flow.forward_key)?;
    let resolved = install_reverse_session_from_forward_match(
        sessions,
        session_map_fd,
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        peer_worker_commands,
        forwarding,
        ha_state,
        dynamic_neighbors,
        &flow.forward_key,
        forward_match,
        now_ns,
        now_secs,
        ha_startup_grace_until_secs,
        protocol,
        tcp_flags,
    );

    let mut decision = resolved.decision;
    decision.resolution = redirect_session_via_fabric_if_needed(
        forwarding,
        enforce_session_ha_resolution(
            forwarding,
            ha_state,
            now_secs,
            lookup_forwarding_resolution_for_session(forwarding, dynamic_neighbors, flow, decision),
            ingress_ifindex,
            ha_startup_grace_until_secs,
        ),
        ingress_ifindex,
        resolved.metadata.ingress_zone.as_ref(),
    );
    let metadata = maybe_promote_synced_session(
        sessions,
        session_map_fd,
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        peer_worker_commands,
        forwarding,
        &flow.forward_key,
        decision,
        resolved.metadata,
        ingress_ifindex,
        now_ns,
        protocol,
        tcp_flags,
    );
    Some(ResolvedFlowSessionDecision {
        decision,
        metadata,
        created: true,
    })
}

fn redirect_session_via_fabric_if_needed(
    forwarding: &ForwardingState,
    resolution: ForwardingResolution,
    ingress_ifindex: i32,
    ingress_zone: &str,
) -> ForwardingResolution {
    if resolution.disposition != ForwardingDisposition::HAInactive {
        return resolution;
    }
    if ingress_is_fabric(forwarding, ingress_ifindex) {
        return resolution;
    }
    resolve_zone_encoded_fabric_redirect(forwarding, ingress_zone)
        .or_else(|| resolve_fabric_redirect(forwarding))
        .unwrap_or(resolution)
}

fn enforce_session_ha_resolution(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    resolution: ForwardingResolution,
    ingress_ifindex: i32,
    ha_startup_grace_until_secs: u64,
) -> ForwardingResolution {
    let enforced = enforce_ha_resolution_snapshot(forwarding, ha_state, now_secs, resolution);
    if enforced.disposition == ForwardingDisposition::HAInactive
        && ingress_is_fabric(forwarding, ingress_ifindex)
    {
        return resolution;
    }
    if enforced.disposition == ForwardingDisposition::HAInactive
        && should_bypass_unseeded_tunnel_ha(
            forwarding,
            ha_state,
            now_secs,
            resolution,
            ingress_ifindex,
            ha_startup_grace_until_secs,
        )
    {
        return resolution;
    }
    enforced
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn test_resolution() -> ForwardingResolution {
        ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 12,
            tx_ifindex: 12,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 50, 1))),
            neighbor_mac: Some([0, 1, 2, 3, 4, 5]),
            src_mac: Some([6, 7, 8, 9, 10, 11]),
            tx_vlan_id: 0,
        }
    }

    fn test_metadata() -> SessionMetadata {
        SessionMetadata {
            ingress_zone: Arc::<str>::from("lan"),
            egress_zone: Arc::<str>::from("wan"),
            owner_rg_id: 1,
            fabric_ingress: false,
            is_reverse: false,
            synced: false,
            nat64_reverse: None,
        }
    }

    fn test_decision() -> SessionDecision {
        SessionDecision {
            resolution: test_resolution(),
            nat: NatDecision::default(),
        }
    }

    fn test_forwarding_state() -> ForwardingState {
        let mut forwarding = ForwardingState::default();
        forwarding.connected_v4.push(ConnectedRouteV4 {
            prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(10, 0, 61, 0), 24).unwrap()),
            ifindex: 6,
            tunnel_endpoint_id: 0,
        });
        forwarding.neighbors.insert(
            (6, IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
            NeighborEntry {
                mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            },
        );
        forwarding.egress.insert(
            6,
            EgressInterface {
                bind_ifindex: 6,
                vlan_id: 0,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
                zone: "lan".to_string(),
                redundancy_group: 1,
                primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
                primary_v6: None,
            },
        );
        forwarding.egress.insert(
            12,
            EgressInterface {
                bind_ifindex: 11,
                vlan_id: 80,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x80, 0x08],
                zone: "wan".to_string(),
                redundancy_group: 1,
                primary_v4: Some(Ipv4Addr::new(172, 16, 80, 8)),
                primary_v6: None,
            },
        );
        forwarding
    }

    fn test_forwarding_state_with_fabric() -> ForwardingState {
        let mut forwarding = test_forwarding_state();
        forwarding.zone_name_to_id.insert("lan".to_string(), 1);
        forwarding.zone_name_to_id.insert("sfmix".to_string(), 2);
        forwarding.fabrics.push(FabricLink {
            parent_ifindex: 21,
            overlay_ifindex: 101,
            peer_addr: IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2)),
            peer_mac: [0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
            local_mac: [0x02, 0xbf, 0x72, 0xff, 0x00, 0x01],
        });
        forwarding
    }

    fn test_forwarding_state_split_rgs() -> ForwardingState {
        let mut forwarding = test_forwarding_state_with_fabric();
        forwarding.egress.insert(
            6,
            EgressInterface {
                bind_ifindex: 6,
                vlan_id: 0,
                mtu: 1500,
                src_mac: [0x02, 0xbf, 0x72, 0x00, 0x61, 0x01],
                zone: "lan".to_string(),
                redundancy_group: 2,
                primary_v4: Some(Ipv4Addr::new(10, 0, 61, 1)),
                primary_v6: None,
            },
        );
        forwarding
    }

    fn test_forwarding_state_split_rgs_with_tunnel() -> ForwardingState {
        let mut forwarding = test_forwarding_state_split_rgs();
        forwarding.tunnel_endpoint_by_ifindex.insert(586, 1);
        forwarding
    }

    fn test_key() -> SessionKey {
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            src_port: 55068,
            dst_port: 5201,
        }
    }

    #[test]
    fn maybe_promote_synced_session_sets_fabric_ingress_on_fabric_hit() {
        let mut sessions = SessionTable::new();
        let key = test_key();
        let decision = test_decision();
        let mut metadata = test_metadata();
        metadata.synced = true;
        assert!(sessions.install_with_protocol(
            key.clone(),
            decision,
            metadata.clone(),
            1_000_000,
            PROTO_TCP,
            0x10,
        ));

        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
        let forwarding = test_forwarding_state_with_fabric();

        let promoted = maybe_promote_synced_session(
            &mut sessions,
            -1,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &peer_worker_commands,
            &forwarding,
            &key,
            decision,
            metadata,
            21,
            2_000_000,
            PROTO_TCP,
            0x10,
        );

        assert!(promoted.fabric_ingress);
        assert!(!promoted.synced);
    }

    #[test]
    fn lookup_session_across_scopes_returns_shared_entry() {
        let mut sessions = SessionTable::new();
        let key = test_key();
        let entry = SyncedSessionEntry {
            key: key.clone(),
            decision: test_decision(),
            metadata: SessionMetadata {
                synced: true,
                ..test_metadata()
            },
            protocol: PROTO_TCP,
            tcp_flags: 0,
        };
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        shared_sessions
            .lock()
            .expect("shared lock")
            .insert(key.clone(), entry.clone());

        let resolved = lookup_session_across_scopes(
            &mut sessions,
            &shared_sessions,
            &shared_forward_wire_sessions,
            &key,
            1,
            0,
        )
        .expect("shared hit");
        assert!(resolved.shared_entry.is_some());
        assert_eq!(resolved.key.as_ref(&key), &key);
        assert_eq!(resolved.lookup.decision, entry.decision);
        assert_eq!(resolved.lookup.metadata, entry.metadata);
    }

    #[test]
    fn lookup_session_across_scopes_returns_shared_forward_wire_entry() {
        let mut sessions = SessionTable::new();
        let key = test_key();
        let decision = SessionDecision {
            resolution: test_resolution(),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_src_port: Some(key.src_port),
                ..NatDecision::default()
            },
        };
        let entry = SyncedSessionEntry {
            key: key.clone(),
            decision,
            metadata: SessionMetadata {
                synced: true,
                ..test_metadata()
            },
            protocol: PROTO_TCP,
            tcp_flags: 0,
        };
        let translated_key = forward_wire_key(&key, decision.nat);
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        shared_forward_wire_sessions
            .lock()
            .expect("shared forward-wire lock")
            .insert(translated_key.clone(), entry.clone());

        let resolved = lookup_session_across_scopes(
            &mut sessions,
            &shared_sessions,
            &shared_forward_wire_sessions,
            &translated_key,
            1,
            0,
        )
        .expect("shared forward-wire hit");
        assert!(resolved.shared_entry.is_some());
        assert_eq!(resolved.key.as_ref(&translated_key), &key);
        assert_eq!(resolved.lookup.decision, entry.decision);
        assert_eq!(resolved.lookup.metadata, entry.metadata);
    }

    #[test]
    fn lookup_forward_nat_across_scopes_returns_shared_nat_entry() {
        let sessions = SessionTable::new();
        let key = SessionKey {
            addr_family: libc::AF_INET6 as u8,
            protocol: PROTO_ICMPV6,
            src_ip: IpAddr::V6("fd35:1940:27:100::102".parse::<Ipv6Addr>().unwrap()),
            dst_ip: IpAddr::V6("2607:f8b0:4005:814::200e".parse::<Ipv6Addr>().unwrap()),
            src_port: 0x8234,
            dst_port: 0,
        };
        let decision = SessionDecision {
            resolution: test_resolution(),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V6(
                    "2602:fd41:70:100::102".parse::<Ipv6Addr>().unwrap(),
                )),
                nptv6: true,
                ..NatDecision::default()
            },
        };
        let entry = SyncedSessionEntry {
            key: key.clone(),
            decision,
            metadata: test_metadata(),
            protocol: PROTO_ICMPV6,
            tcp_flags: 0,
        };
        let reply_key = reverse_session_key(&key, decision.nat);
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        shared_nat_sessions
            .lock()
            .expect("shared nat lock")
            .insert(reply_key.clone(), entry.clone());

        let hit = lookup_forward_nat_across_scopes(&sessions, &shared_nat_sessions, &reply_key)
            .expect("shared forward nat hit");
        assert_eq!(hit.key, entry.key);
        assert_eq!(hit.decision, entry.decision);
        assert_eq!(hit.metadata, entry.metadata);
    }

    #[test]
    fn lookup_forward_nat_across_scopes_returns_shared_canonical_reverse_entry() {
        let sessions = SessionTable::new();
        let key = test_key();
        let decision = SessionDecision {
            resolution: test_resolution(),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_src_port: Some(key.src_port),
                ..NatDecision::default()
            },
        };
        let entry = SyncedSessionEntry {
            key: key.clone(),
            decision,
            metadata: SessionMetadata {
                synced: true,
                ..test_metadata()
            },
            protocol: PROTO_TCP,
            tcp_flags: 0,
        };
        let canonical_reply = reverse_canonical_key(&key, decision.nat);
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        shared_nat_sessions
            .lock()
            .expect("shared nat lock")
            .insert(canonical_reply.clone(), entry.clone());

        let hit =
            lookup_forward_nat_across_scopes(&sessions, &shared_nat_sessions, &canonical_reply)
                .expect("shared canonical reverse hit");
        assert_eq!(hit.key, entry.key);
        assert_eq!(hit.decision, entry.decision);
        assert_eq!(hit.metadata, entry.metadata);
    }

    #[test]
    fn publish_and_remove_shared_session_tracks_forward_wire_alias() {
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let key = test_key();
        let decision = SessionDecision {
            resolution: test_resolution(),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_src_port: Some(key.src_port),
                ..NatDecision::default()
            },
        };
        let entry = SyncedSessionEntry {
            key: key.clone(),
            decision,
            metadata: test_metadata(),
            protocol: PROTO_TCP,
            tcp_flags: 0,
        };
        let translated_key = forward_wire_key(&key, decision.nat);

        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &entry,
        );
        let alias_hit =
            lookup_shared_forward_wire_match(&shared_forward_wire_sessions, &translated_key)
                .expect("forward-wire alias should be published");
        assert_eq!(alias_hit.key, key);

        remove_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &entry.key,
        );
        assert!(
            lookup_shared_forward_wire_match(&shared_forward_wire_sessions, &translated_key)
                .is_none()
        );
    }

    #[test]
    fn publish_and_remove_shared_session_tracks_canonical_reverse_alias() {
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let key = test_key();
        let decision = SessionDecision {
            resolution: test_resolution(),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_src_port: Some(key.src_port),
                ..NatDecision::default()
            },
        };
        let entry = SyncedSessionEntry {
            key: key.clone(),
            decision,
            metadata: test_metadata(),
            protocol: PROTO_TCP,
            tcp_flags: 0,
        };
        let canonical_reply = reverse_canonical_key(&key, decision.nat);

        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &entry,
        );
        let alias_hit = lookup_shared_forward_nat_match(&shared_nat_sessions, &canonical_reply)
            .expect("canonical reverse alias should be published");
        assert_eq!(alias_hit.key, key);

        remove_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &entry.key,
        );
        assert!(lookup_shared_forward_nat_match(&shared_nat_sessions, &canonical_reply).is_none());
    }

    #[test]
    fn resolve_flow_session_decision_uses_canonical_key_for_translated_forward_hit() {
        let mut sessions = SessionTable::new();
        let key = test_key();
        let decision = SessionDecision {
            resolution: test_resolution(),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_src_port: Some(key.src_port),
                ..NatDecision::default()
            },
        };
        let translated_key = forward_wire_key(&key, decision.nat);
        let entry = SyncedSessionEntry {
            key: key.clone(),
            decision,
            metadata: SessionMetadata {
                synced: true,
                ..test_metadata()
            },
            protocol: PROTO_TCP,
            tcp_flags: 0,
        };
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &entry,
        );

        let flow = SessionFlow {
            src_ip: translated_key.src_ip,
            dst_ip: translated_key.dst_ip,
            forward_key: translated_key.clone(),
        };
        let forwarding = ForwardingState::default();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let peer_worker_commands = Vec::new();
        let resolved = resolve_flow_session_decision(
            &mut sessions,
            -1,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &peer_worker_commands,
            &forwarding,
            &BTreeMap::new(),
            &dynamic_neighbors,
            &flow,
            1_000_000,
            1,
            PROTO_TCP,
            0x10,
            0,
            0,
        )
        .expect("translated forward hit should resolve");

        assert!(!resolved.created);
        assert!(!resolved.metadata.synced);
        assert!(sessions.lookup(&translated_key, 1_000_000, 0x10).is_none());
        let local_hit = sessions
            .find_forward_wire_match(&translated_key)
            .expect("local canonical session should keep forward-wire alias");
        assert_eq!(local_hit.key, key);
        assert_eq!(resolved.decision.nat, decision.nat);
    }

    #[test]
    fn apply_worker_commands_replaces_stale_local_session_for_inactive_owner_rg() {
        let commands = Arc::new(Mutex::new(VecDeque::new()));
        let mut sessions = SessionTable::new();
        let key = test_key();
        let live_metadata = test_metadata();
        assert!(sessions.install_with_protocol(
            key.clone(),
            test_decision(),
            live_metadata,
            1_000_000,
            PROTO_TCP,
            0x10,
        ));
        let synced_metadata = SessionMetadata {
            synced: true,
            ..test_metadata()
        };
        let synced_decision = SessionDecision {
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_src_port: Some(key.src_port),
                ..NatDecision::default()
            },
            ..test_decision()
        };
        commands
            .lock()
            .expect("commands lock")
            .push_back(WorkerCommand::UpsertSynced(SyncedSessionEntry {
                key: key.clone(),
                decision: synced_decision,
                metadata: synced_metadata.clone(),
                protocol: PROTO_TCP,
                tcp_flags: 0x10,
            }));
        let mut ha_state = BTreeMap::new();
        ha_state.insert(
            1,
            HAGroupRuntime {
                active: false,
                watchdog_timestamp: 0,
            },
        );
        let forwarding = test_forwarding_state();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));

        apply_worker_commands(
            &commands,
            &mut sessions,
            -1,
            &forwarding,
            &ha_state,
            &dynamic_neighbors,
        );

        let hit = sessions.lookup(&key, 2_000_000, 0x10).expect("synced hit");
        assert_eq!(hit.metadata, synced_metadata);
        assert_eq!(hit.decision, synced_decision);
    }

    #[test]
    fn apply_worker_commands_preserves_local_session_for_active_owner_rg() {
        let commands = Arc::new(Mutex::new(VecDeque::new()));
        let mut sessions = SessionTable::new();
        let key = test_key();
        let live_decision = test_decision();
        let live_metadata = test_metadata();
        assert!(sessions.install_with_protocol(
            key.clone(),
            live_decision,
            live_metadata.clone(),
            1_000_000,
            PROTO_TCP,
            0x10,
        ));
        let synced_decision = SessionDecision {
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_src_port: Some(key.src_port),
                ..NatDecision::default()
            },
            ..test_decision()
        };
        commands
            .lock()
            .expect("commands lock")
            .push_back(WorkerCommand::UpsertSynced(SyncedSessionEntry {
                key: key.clone(),
                decision: synced_decision,
                metadata: SessionMetadata {
                    synced: true,
                    ..test_metadata()
                },
                protocol: PROTO_TCP,
                tcp_flags: 0x10,
            }));
        let mut ha_state = BTreeMap::new();
        ha_state.insert(
            1,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: monotonic_nanos() / 1_000_000_000,
            },
        );
        let forwarding = test_forwarding_state();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));

        apply_worker_commands(
            &commands,
            &mut sessions,
            -1,
            &forwarding,
            &ha_state,
            &dynamic_neighbors,
        );

        let hit = sessions.lookup(&key, 2_000_000, 0x10).expect("live hit");
        assert_eq!(hit.metadata, live_metadata);
        assert_eq!(hit.decision, live_decision);
    }

    #[test]
    fn apply_worker_commands_demotes_local_sessions_for_owner_rg() {
        let commands = Arc::new(Mutex::new(VecDeque::new()));
        let mut sessions = SessionTable::new();
        let key = test_key();
        let mut live_metadata = test_metadata();
        live_metadata.owner_rg_id = 1;
        assert!(sessions.install_with_protocol(
            key.clone(),
            test_decision(),
            live_metadata,
            1_000_000,
            PROTO_TCP,
            0x10,
        ));
        commands
            .lock()
            .expect("commands lock")
            .push_back(WorkerCommand::DemoteOwnerRG(1));
        let forwarding = test_forwarding_state();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));

        apply_worker_commands(
            &commands,
            &mut sessions,
            -1,
            &forwarding,
            &BTreeMap::new(),
            &dynamic_neighbors,
        );

        let hit = sessions.lookup(&key, 2_000_000, 0x10).expect("demoted hit");
        assert!(hit.metadata.synced);
    }

    #[test]
    fn apply_worker_commands_marks_reverse_local_sessions_synced_for_owner_rg() {
        let commands = Arc::new(Mutex::new(VecDeque::new()));
        let mut sessions = SessionTable::new();
        let mut key = test_key();
        key.src_ip = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200));
        key.dst_ip = IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8));
        let mut reverse_metadata = test_metadata();
        reverse_metadata.owner_rg_id = 1;
        reverse_metadata.is_reverse = true;
        assert!(sessions.install_with_protocol(
            key.clone(),
            test_decision(),
            reverse_metadata,
            1_000_000,
            PROTO_TCP,
            0x10,
        ));
        commands
            .lock()
            .expect("commands lock")
            .push_back(WorkerCommand::DemoteOwnerRG(1));
        let forwarding = test_forwarding_state();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));

        apply_worker_commands(
            &commands,
            &mut sessions,
            -1,
            &forwarding,
            &BTreeMap::new(),
            &dynamic_neighbors,
        );

        let hit = sessions
            .lookup(&key, 2_000_000, 0x10)
            .expect("demoted reverse hit");
        assert!(hit.metadata.synced);
    }

    #[test]
    fn apply_worker_commands_refreshes_live_reverse_sessions_for_activated_owner_rg() {
        let commands = Arc::new(Mutex::new(VecDeque::new()));
        let mut sessions = SessionTable::new();
        let key = SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: PROTO_TCP,
            src_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
            src_port: 5201,
            dst_port: 42424,
        };
        let decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::HAInactive,
                local_ifindex: 0,
                egress_ifindex: 6,
                tx_ifindex: 6,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]),
                tx_vlan_id: 0,
            },
            nat: NatDecision::default(),
        };
        let metadata = SessionMetadata {
            ingress_zone: Arc::<str>::from("wan"),
            egress_zone: Arc::<str>::from("lan"),
            owner_rg_id: 0,
            fabric_ingress: false,
            is_reverse: true,
            synced: false,
            nat64_reverse: None,
        };
        assert!(sessions.install_with_protocol(
            key.clone(),
            decision,
            metadata,
            1_000_000,
            PROTO_TCP,
            0x10,
        ));
        commands
            .lock()
            .expect("commands lock")
            .push_back(WorkerCommand::RefreshOwnerRGs(vec![1]));
        let forwarding = test_forwarding_state();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let mut ha_state = BTreeMap::new();
        ha_state.insert(
            1,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: monotonic_nanos() / 1_000_000_000,
            },
        );

        apply_worker_commands(
            &commands,
            &mut sessions,
            -1,
            &forwarding,
            &ha_state,
            &dynamic_neighbors,
        );

        let hit = sessions
            .lookup(&key, 2_000_000, 0x10)
            .expect("refreshed reverse hit");
        assert_eq!(
            hit.decision.resolution.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(hit.decision.resolution.egress_ifindex, 6);
        assert_eq!(hit.metadata.owner_rg_id, 1);
    }

    #[test]
    fn demote_shared_owner_rgs_preserves_reverse_entries_and_marks_all_synced() {
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let forward = SyncedSessionEntry {
            key: test_key(),
            decision: test_decision(),
            metadata: test_metadata(),
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
        };
        let reverse = SyncedSessionEntry {
            key: reverse_session_key(&forward.key, forward.decision.nat),
            decision: test_decision(),
            metadata: SessionMetadata {
                is_reverse: true,
                ..test_metadata()
            },
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
        };
        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &forward,
        );
        shared_sessions
            .lock()
            .expect("shared sessions")
            .insert(reverse.key.clone(), reverse.clone());

        demote_shared_owner_rgs(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &[1],
        );

        let shared_forward = shared_sessions
            .lock()
            .expect("shared sessions")
            .get(&forward.key)
            .cloned()
            .expect("forward entry");
        assert!(shared_forward.metadata.synced);
        let shared_reverse = shared_sessions
            .lock()
            .expect("shared sessions")
            .get(&reverse.key)
            .cloned()
            .expect("reverse entry");
        assert!(shared_reverse.metadata.synced);
        let reverse_alias = reverse_session_key(&forward.key, forward.decision.nat);
        let nat_alias = shared_nat_sessions
            .lock()
            .expect("shared nat")
            .get(&reverse_alias)
            .cloned()
            .expect("nat alias");
        assert!(nat_alias.metadata.synced);
    }

    #[test]
    fn synthesized_synced_reverse_entry_preserves_fabric_ingress_and_reverse_flag() {
        let forwarding = test_forwarding_state();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let mut metadata = test_metadata();
        metadata.fabric_ingress = true;
        metadata.synced = true;
        let entry = SyncedSessionEntry {
            key: test_key(),
            decision: test_decision(),
            metadata,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
        };

        let reverse = synthesized_synced_reverse_entry(
            &forwarding,
            &BTreeMap::new(),
            &dynamic_neighbors,
            &entry,
            1,
        )
        .expect("reverse companion");

        assert!(reverse.metadata.is_reverse);
        assert!(reverse.metadata.synced);
        assert!(reverse.metadata.fabric_ingress);
        assert_eq!(reverse.metadata.ingress_zone.as_ref(), "wan");
        assert_eq!(reverse.metadata.egress_zone.as_ref(), "lan");
        assert_eq!(
            reverse.key,
            reverse_session_key(&entry.key, entry.decision.nat)
        );
    }

    #[test]
    fn synthesized_synced_reverse_entry_tracks_local_client_when_owner_rg_active() {
        let forwarding = test_forwarding_state();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let mut metadata = test_metadata();
        metadata.fabric_ingress = true;
        metadata.synced = true;
        let entry = SyncedSessionEntry {
            key: test_key(),
            decision: test_decision(),
            metadata,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
        };
        let mut ha_state = BTreeMap::new();
        ha_state.insert(
            1,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: 1,
            },
        );

        let reverse =
            synthesized_synced_reverse_entry(&forwarding, &ha_state, &dynamic_neighbors, &entry, 1)
                .expect("reverse companion");

        assert_eq!(
            reverse.decision.resolution.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(reverse.decision.resolution.egress_ifindex, 6);
    }

    #[test]
    fn session_hit_ha_inactive_uses_zone_encoded_fabric_redirect() {
        let forwarding = test_forwarding_state_with_fabric();
        let redirected = redirect_session_via_fabric_if_needed(
            &forwarding,
            ForwardingResolution {
                disposition: ForwardingDisposition::HAInactive,
                local_ifindex: 0,
                egress_ifindex: 6,
                tx_ifindex: 6,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]),
                tx_vlan_id: 0,
            },
            362,
            "sfmix",
        );
        assert_eq!(
            redirected.disposition,
            ForwardingDisposition::FabricRedirect
        );
        assert_eq!(redirected.egress_ifindex, 21);
        assert_eq!(redirected.tx_ifindex, 21);
        assert_eq!(
            redirected.src_mac,
            Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x02])
        );
    }

    #[test]
    fn fabric_ingress_session_hit_bypasses_ha_inactive_gate() {
        let forwarding = test_forwarding_state_with_fabric();
        let ha_state = BTreeMap::from([(
            1,
            HAGroupRuntime {
                active: false,
                watchdog_timestamp: 1,
            },
        )]);
        let resolved = enforce_session_ha_resolution(
            &forwarding,
            &ha_state,
            1,
            ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 6,
                tx_ifindex: 6,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]),
                tx_vlan_id: 0,
            },
            21,
            0,
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved.egress_ifindex, 6);
    }

    #[test]
    fn tunnel_ingress_session_hit_bypasses_unseeded_ha_during_startup_grace() {
        let forwarding = test_forwarding_state_split_rgs_with_tunnel();
        let ha_state = BTreeMap::from([(
            2,
            HAGroupRuntime {
                active: false,
                watchdog_timestamp: 0,
            },
        )]);
        let resolved = enforce_session_ha_resolution(
            &forwarding,
            &ha_state,
            100,
            ForwardingResolution {
                disposition: ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 6,
                tx_ifindex: 6,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102))),
                neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]),
                src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x61, 0x01]),
                tx_vlan_id: 0,
            },
            586,
            110,
        );
        assert_eq!(
            resolved.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved.egress_ifindex, 6);
    }

    #[test]
    fn reverse_session_from_tunnel_forward_bypasses_unseeded_ha_during_startup_grace() {
        let forwarding = test_forwarding_state_split_rgs_with_tunnel();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let ha_state = BTreeMap::from([(
            2,
            HAGroupRuntime {
                active: false,
                watchdog_timestamp: 0,
            },
        )]);
        let reverse = build_reverse_session_from_forward_match(
            &forwarding,
            &ha_state,
            &dynamic_neighbors,
            ForwardSessionMatch {
                key: SessionKey {
                    addr_family: libc::AF_INET as u8,
                    protocol: PROTO_TCP,
                    src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
                    dst_ip: IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41)),
                    src_port: 42424,
                    dst_port: 5201,
                },
                decision: SessionDecision {
                    resolution: ForwardingResolution {
                        disposition: ForwardingDisposition::ForwardCandidate,
                        local_ifindex: 0,
                        egress_ifindex: 12,
                        tx_ifindex: 12,
                        tunnel_endpoint_id: 1,
                        next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 255, 192, 41))),
                        neighbor_mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x02]),
                        src_mac: Some([0x02, 0xbf, 0x72, 0x00, 0x80, 0x08]),
                        tx_vlan_id: 80,
                    },
                    nat: NatDecision {
                        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(10, 255, 192, 42))),
                        ..NatDecision::default()
                    },
                },
                metadata: SessionMetadata {
                    ingress_zone: Arc::<str>::from("lan"),
                    egress_zone: Arc::<str>::from("sfmix"),
                    owner_rg_id: 2,
                    fabric_ingress: false,
                    is_reverse: false,
                    synced: false,
                    nat64_reverse: None,
                },
            },
            100,
            110,
        );
        assert_eq!(
            reverse.decision.resolution.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(reverse.decision.resolution.egress_ifindex, 6);
        assert_eq!(reverse.metadata.owner_rg_id, 2);
    }

    #[test]
    fn prewarm_reverse_synced_sessions_for_owner_rgs_adds_reverse_companion() {
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let worker_commands = vec![Arc::new(Mutex::new(VecDeque::new()))];
        let forwarding = test_forwarding_state();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let mut ha_state = BTreeMap::new();
        ha_state.insert(
            1,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: 1,
            },
        );
        let entry = SyncedSessionEntry {
            key: test_key(),
            decision: test_decision(),
            metadata: SessionMetadata {
                synced: true,
                fabric_ingress: true,
                ..test_metadata()
            },
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
        };
        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &entry,
        );

        prewarm_reverse_synced_sessions_for_owner_rgs(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &worker_commands,
            -1,
            &forwarding,
            &ha_state,
            &dynamic_neighbors,
            &[1],
            1,
        );

        let reverse_key = reverse_session_key(&entry.key, entry.decision.nat);
        let reverse = shared_sessions
            .lock()
            .expect("shared sessions")
            .get(&reverse_key)
            .cloned()
            .expect("reverse entry");
        assert!(reverse.metadata.is_reverse);
        assert!(reverse.metadata.synced);
        assert_eq!(worker_commands[0].lock().expect("commands").len(), 1);
    }

    #[test]
    fn prewarm_reverse_synced_sessions_refreshes_reverse_for_other_activated_rg() {
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let worker_commands = vec![Arc::new(Mutex::new(VecDeque::new()))];
        let forwarding = test_forwarding_state_split_rgs();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let mut ha_state = BTreeMap::new();
        ha_state.insert(
            2,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: 1,
            },
        );
        let mut entry = SyncedSessionEntry {
            key: test_key(),
            decision: test_decision(),
            metadata: SessionMetadata {
                synced: true,
                fabric_ingress: true,
                ..test_metadata()
            },
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
        };
        entry.metadata.owner_rg_id = 1;
        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &entry,
        );

        prewarm_reverse_synced_sessions_for_owner_rgs(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &worker_commands,
            -1,
            &forwarding,
            &ha_state,
            &dynamic_neighbors,
            &[2],
            1,
        );

        let reverse_key = reverse_session_key(&entry.key, entry.decision.nat);
        let reverse = shared_sessions
            .lock()
            .expect("shared sessions")
            .get(&reverse_key)
            .cloned()
            .expect("reverse entry");
        assert!(reverse.metadata.is_reverse);
        assert!(reverse.metadata.synced);
        assert_eq!(
            reverse.decision.resolution.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(reverse.decision.resolution.egress_ifindex, 6);
        assert_eq!(reverse.metadata.owner_rg_id, 2);
    }
}
