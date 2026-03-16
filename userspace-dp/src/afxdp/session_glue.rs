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
    if let Some(cached) = cached_session_resolution(forwarding, decision.resolution) {
        return cached;
    }
    let target = resolution_target_for_session(flow, decision);
    let resolved = lookup_forwarding_resolution_with_dynamic(forwarding, dynamic_neighbors, target);
    match resolved.disposition {
        ForwardingDisposition::NoRoute | ForwardingDisposition::MissingNeighbor => {
            cached_session_resolution(forwarding, decision.resolution).unwrap_or(resolved)
        }
        _ => resolved,
    }
}

pub(super) fn apply_worker_commands(
    commands: &Arc<Mutex<VecDeque<WorkerCommand>>>,
    sessions: &mut SessionTable,
    session_map_fd: c_int,
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
    for cmd in pending {
        match cmd {
            WorkerCommand::UpsertSynced(entry) => {
                let key = entry.key.clone();
                let is_reverse = entry.metadata.is_reverse;
                sessions.upsert_synced(
                    entry.key,
                    entry.decision,
                    entry.metadata,
                    now_ns,
                    entry.protocol,
                    entry.tcp_flags,
                );
                let _ = publish_live_session_entry(
                    session_map_fd,
                    &key,
                    entry.decision.nat,
                    is_reverse,
                );
            }
            WorkerCommand::DeleteSynced(key) => {
                let delete_alias = sessions.lookup(&key, now_ns, 0).map(|lookup| {
                    (lookup.decision.nat, lookup.metadata.is_reverse)
                });
                sessions.delete(&key);
                if let Some((nat, is_reverse)) = delete_alias {
                    delete_live_session_entry(session_map_fd, &key, nat, is_reverse);
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

pub(super) fn synced_replica_entry(entry: &SyncedSessionEntry) -> SyncedSessionEntry {
    let mut replica = entry.clone();
    replica.metadata.synced = true;
    replica
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
pub(super) struct ResolvedSessionLookup {
    pub(super) key: SessionKey,
    pub(super) lookup: SessionLookup,
    pub(super) shared_entry: Option<SyncedSessionEntry>,
}

impl ResolvedSessionLookup {
    fn local(key: SessionKey, lookup: SessionLookup) -> Self {
        Self {
            key,
            lookup,
            shared_entry: None,
        }
    }

    fn shared(entry: SyncedSessionEntry) -> Self {
        Self {
            key: entry.key.clone(),
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
        .map(|lookup| ResolvedSessionLookup::local(key.clone(), lookup))
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
    resolved: ResolvedSessionLookup,
    now_ns: u64,
    tcp_flags: u8,
) -> SessionLookup {
    if let Some(shared) = resolved.shared_entry {
        let replica = synced_replica_entry(&shared);
        sessions.upsert_synced(
            replica.key.clone(),
            replica.decision,
            replica.metadata.clone(),
            now_ns,
            replica.protocol,
            tcp_flags,
        );
        return SessionLookup {
            decision: replica.decision,
            metadata: replica.metadata,
        };
    }
    resolved.lookup
}

fn build_reverse_session_from_forward_match(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    forward_match: ForwardSessionMatch,
    now_secs: u64,
) -> SessionLookup {
    let resolution = reverse_resolution_for_session(
        forwarding,
        ha_state,
        dynamic_neighbors,
        forward_match.key.src_ip,
        forward_match.metadata.ingress_zone.as_ref(),
        forward_match.metadata.fabric_ingress,
        now_secs,
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
        owner_rg_id: forward_match.metadata.owner_rg_id,
        fabric_ingress: forward_match.metadata.fabric_ingress,
        is_reverse: true,
        synced: false,
        nat64_reverse: None,
    };
    SessionLookup { decision, metadata }
}

pub(super) fn reverse_resolution_for_session(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    target_ip: IpAddr,
    ingress_zone: &str,
    fabric_ingress: bool,
    now_secs: u64,
) -> ForwardingResolution {
    let resolved = lookup_forwarding_resolution_with_dynamic(forwarding, dynamic_neighbors, target_ip);
    if fabric_ingress
        && owner_rg_for_flow(forwarding, resolved.egress_ifindex) > 0
        && !matches!(
            ha_state.get(&owner_rg_for_flow(forwarding, resolved.egress_ifindex)),
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
    enforce_ha_resolution_snapshot(forwarding, ha_state, now_secs, resolved)
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
    protocol: u8,
    tcp_flags: u8,
) -> SessionLookup {
    let reverse = build_reverse_session_from_forward_match(
        forwarding,
        ha_state,
        dynamic_neighbors,
        forward_match,
        now_secs,
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
        promoted.owner_rg_id = owner_rg_for_flow(forwarding, decision.resolution.egress_ifindex);
    }
    if sessions.promote_synced(key, decision, promoted.clone(), now_ns, protocol, tcp_flags) {
        let _ = publish_live_session_entry(session_map_fd, key, decision.nat, promoted.is_reverse);
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
) -> Option<ResolvedFlowSessionDecision> {
    let (resolved_key, resolved, created) = if let Some(hit) = lookup_session_across_scopes(
        sessions,
        shared_sessions,
        shared_forward_wire_sessions,
        &flow.forward_key,
        now_ns,
        tcp_flags,
    ) {
        let resolved_key = hit.key.clone();
        (
            resolved_key,
            materialize_shared_session_hit(sessions, hit, now_ns, tcp_flags),
            false,
        )
    } else {
        let forward_match =
            lookup_forward_nat_across_scopes(sessions, shared_nat_sessions, &flow.forward_key)?;
        (
            flow.forward_key.clone(),
            install_reverse_session_from_forward_match(
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
                protocol,
                tcp_flags,
            ),
            true,
        )
    };

    let mut decision = resolved.decision;
    decision.resolution = redirect_via_fabric_if_needed(
        forwarding,
        enforce_ha_resolution_snapshot(
            forwarding,
            ha_state,
            now_secs,
            lookup_forwarding_resolution_for_session(forwarding, dynamic_neighbors, flow, decision),
        ),
        ingress_ifindex,
    );
    let metadata = maybe_promote_synced_session(
        sessions,
        session_map_fd,
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        peer_worker_commands,
        forwarding,
        &resolved_key,
        decision,
        resolved.metadata,
        now_ns,
        protocol,
        tcp_flags,
    );
    Some(ResolvedFlowSessionDecision {
        decision,
        metadata,
        created,
    })
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
        assert_eq!(resolved.key, key);
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
        assert_eq!(resolved.key, key);
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
        let alias_hit = lookup_shared_forward_wire_match(
            &shared_forward_wire_sessions,
            &translated_key,
        )
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
}
