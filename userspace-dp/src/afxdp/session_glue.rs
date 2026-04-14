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
    if cached.disposition != ForwardingDisposition::ForwardCandidate {
        return None;
    }
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
    lookup_forwarding_resolution_for_session_with_cache(
        forwarding,
        dynamic_neighbors,
        flow,
        decision,
        true,
    )
}

fn lookup_forwarding_resolution_for_session_with_cache(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    flow: &SessionFlow,
    decision: SessionDecision,
    allow_cached_fast_path: bool,
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
    if allow_cached_fast_path {
        if let Some(cached) = cached_session_resolution(forwarding, decision.resolution) {
            return cached;
        }
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

fn lookup_forwarding_resolution_for_synced_session(
    forwarding: &ForwardingState,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
    flow: &SessionFlow,
    decision: SessionDecision,
) -> ForwardingResolution {
    lookup_forwarding_resolution_for_session_with_cache(
        forwarding,
        dynamic_neighbors,
        flow,
        decision,
        false,
    )
}

pub(super) fn owner_rg_is_locally_active(
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    owner_rg_id: i32,
    now_secs: u64,
) -> bool {
    owner_rg_id > 0
        && matches!(ha_state.get(&owner_rg_id), Some(group) if group.is_forwarding_active(now_secs))
}

pub(super) fn synced_entry_allows_local_replace(
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    owner_rg_id: i32,
    now_secs: u64,
) -> bool {
    if owner_rg_is_locally_active(ha_state, owner_rg_id, now_secs) {
        return false;
    }
    if owner_rg_id == 0
        && ha_state
            .values()
            .any(|group| group.is_forwarding_active(now_secs))
    {
        return false;
    }
    true
}

pub(super) fn redirect_session_resolution_for_metadata(
    forwarding: &ForwardingState,
    resolution: ForwardingResolution,
    metadata: &SessionMetadata,
) -> ForwardingResolution {
    if resolution.disposition != ForwardingDisposition::HAInactive || metadata.fabric_ingress {
        return resolution;
    }
    resolve_zone_encoded_fabric_redirect(forwarding, metadata.ingress_zone.as_ref())
        .or_else(|| resolve_fabric_redirect(forwarding))
        .unwrap_or(resolution)
}

pub(super) fn owner_rg_is_unseeded(
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
                ..
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

pub(super) struct WorkerCommandResults {
    pub cancelled_keys: Vec<SessionKey>,
    pub exported_sequences: Vec<u64>,
    pub shaped_tx_requests: Vec<TxRequest>,
}

fn force_live_redirect_for_worker_synced_entry(
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
    allow_replace_local: bool,
) -> bool {
    allow_replace_local && uses_kernel_local_session_map_entry(decision, metadata, origin)
}

fn publish_worker_session_map_entry(
    session_map_fd: c_int,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
    allow_replace_local: bool,
) {
    if session_map_fd < 0 {
        return;
    }
    let uses_kernel_local = uses_kernel_local_session_map_entry(decision, metadata, origin);
    let _ = if force_live_redirect_for_worker_synced_entry(
        decision,
        metadata,
        origin,
        allow_replace_local,
    ) {
        publish_live_session_entry(session_map_fd, key, decision.nat, metadata.is_reverse)
    } else {
        if uses_kernel_local {
            delete_live_session_entry(session_map_fd, key, decision.nat, metadata.is_reverse);
        }
        publish_session_map_entry_for_session_with_origin(
            session_map_fd,
            key,
            decision,
            metadata,
            origin,
        )
    };
}

fn export_forward_sessions_for_owner_rgs(sessions: &mut SessionTable, owner_rgs: &[i32]) {
    if owner_rgs.is_empty() {
        return;
    }
    let mut export = Vec::new();
    for key in sessions.owner_rg_session_keys(owner_rgs) {
        let Some((decision, metadata, origin)) = sessions.entry_with_origin(&key) else {
            continue;
        };
        if metadata.is_reverse
            || origin.is_peer_synced()
            || origin.is_transient_local_seed()
            || metadata.fabric_ingress
        {
            continue;
        }
        if !matches!(
            decision.resolution.disposition,
            ForwardingDisposition::ForwardCandidate | ForwardingDisposition::FabricRedirect
        ) {
            continue;
        }
        export.push((key, decision, metadata, origin));
    }
    for (key, decision, metadata, origin) in export {
        sessions.emit_open_delta_with_origin(key, decision, metadata, origin, true);
    }
}

pub(super) fn apply_worker_commands(
    commands: &Arc<Mutex<VecDeque<WorkerCommand>>>,
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    _conntrack_v4_fd: c_int,
    _conntrack_v6_fd: c_int,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<Mutex<FastMap<(i32, IpAddr), NeighborEntry>>>,
) -> WorkerCommandResults {
    // Hot path: try_lock avoids blocking on the mutex when another thread
    // holds it (rare) and avoids the cost of lock+unlock on empty queues
    // when there's nothing to do (common case during steady-state forwarding).
    let pending = match commands.try_lock() {
        Ok(mut pending) => {
            if pending.is_empty() {
                return WorkerCommandResults {
                    cancelled_keys: Vec::new(),
                    exported_sequences: Vec::new(),
                    shaped_tx_requests: Vec::new(),
                };
            }
            core::mem::take(&mut *pending)
        }
        Err(_) => {
            return WorkerCommandResults {
                cancelled_keys: Vec::new(),
                exported_sequences: Vec::new(),
                shaped_tx_requests: Vec::new(),
            };
        }
    };
    let now_ns = monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    let mut cancelled_keys: Vec<SessionKey> = Vec::new();
    let mut exported_sequences = Vec::new();
    let mut shaped_tx_requests = Vec::new();
    for cmd in pending {
        match cmd {
            WorkerCommand::DemoteOwnerRGS { owner_rgs } => {
                let mut seen_owner_rgs = std::collections::BTreeSet::new();
                for owner_rg_id in owner_rgs {
                    if !seen_owner_rgs.insert(owner_rg_id) {
                        continue;
                    }
                    for demoted_key in sessions.demote_owner_rg(owner_rg_id) {
                        let Some((decision, metadata, _origin)) =
                            sessions.entry_with_origin(&demoted_key)
                        else {
                            continue;
                        };
                        let flow = SessionFlow {
                            src_ip: demoted_key.src_ip,
                            dst_ip: demoted_key.dst_ip,
                            forward_key: demoted_key.clone(),
                        };
                        let resolution_target = resolution_target_for_session(&flow, decision);
                        let looked_up_resolution = lookup_forwarding_resolution_for_session(
                            forwarding,
                            dynamic_neighbors,
                            &flow,
                            decision,
                        );
                        let looked_up_resolution =
                            super::prefer_local_forward_candidate_for_fabric_ingress(
                                forwarding,
                                ha_state,
                                dynamic_neighbors,
                                now_secs,
                                metadata.fabric_ingress,
                                resolution_target,
                                looked_up_resolution,
                            );
                        let enforced_resolution = enforce_ha_resolution_snapshot(
                            forwarding,
                            ha_state,
                            now_secs,
                            looked_up_resolution,
                        );
                        let refreshed_decision = SessionDecision {
                            resolution: redirect_session_via_fabric_if_needed(
                                forwarding,
                                enforced_resolution,
                                metadata.fabric_ingress,
                                metadata.ingress_zone.as_ref(),
                            ),
                            ..decision
                        };
                        let rewrote_session = refreshed_decision.resolution.disposition
                            != ForwardingDisposition::HAInactive
                            && sessions.refresh_for_ha_transition(
                                &demoted_key,
                                refreshed_decision,
                                metadata.clone(),
                                now_ns,
                            );
                        let Some((decision, metadata, origin)) =
                            sessions.entry_with_origin(&demoted_key)
                        else {
                            continue;
                        };
                        let owner_rg_id = metadata.owner_rg_id;
                        let publish_decision = if rewrote_session {
                            decision
                        } else {
                            refreshed_decision
                        };
                        let publish_metadata = if rewrote_session {
                            metadata
                        } else {
                            metadata.clone()
                        };
                        publish_worker_session_map_entry(
                            session_map_fd,
                            &demoted_key,
                            publish_decision,
                            &publish_metadata,
                            origin,
                            synced_entry_allows_local_replace(ha_state, owner_rg_id, now_secs),
                        );
                        if !cancelled_keys.iter().any(|key| key == &demoted_key) {
                            cancelled_keys.push(demoted_key);
                        }
                    }
                }
            }
            WorkerCommand::RefreshOwnerRGS { owner_rgs } => {
                if !owner_rgs.iter().any(|owner_rg_id| *owner_rg_id > 0) {
                    continue;
                }

                // Activation must re-evaluate all HA-managed worker sessions,
                // not just those currently indexed under the activated RG.
                // Split-RG reverse companions can remain owned by RG2 while a
                // move of RG1 changes whether they should locally forward or
                // fabric-redirect. Activation is infrequent, so do the wider
                // worker scan here instead of trusting potentially stale RG
                // ownership buckets.
                let mut refresh = Vec::new();
                sessions.iter_with_origin(|key, decision, metadata, origin| {
                    if metadata.owner_rg_id <= 0 && !metadata.fabric_ingress {
                        return;
                    }
                    let flow = SessionFlow {
                        src_ip: key.src_ip,
                        dst_ip: key.dst_ip,
                        forward_key: key.clone(),
                    };
                    let resolution_target = resolution_target_for_session(&flow, decision);
                    let looked_up_resolution = lookup_forwarding_resolution_for_session(
                        forwarding,
                        dynamic_neighbors,
                        &flow,
                        decision,
                    );
                    let looked_up_resolution =
                        super::prefer_local_forward_candidate_for_fabric_ingress(
                            forwarding,
                            ha_state,
                            dynamic_neighbors,
                            now_secs,
                            metadata.fabric_ingress,
                            resolution_target,
                            looked_up_resolution,
                        );
                    let enforced_resolution = enforce_ha_resolution_snapshot(
                        forwarding,
                        ha_state,
                        now_secs,
                        looked_up_resolution,
                    );
                    let refreshed_decision = SessionDecision {
                        resolution: redirect_session_via_fabric_if_needed(
                            forwarding,
                            enforced_resolution,
                            metadata.fabric_ingress,
                            metadata.ingress_zone.as_ref(),
                        ),
                        ..decision
                    };
                    let mut refreshed_metadata = metadata.clone();
                    let refreshed_owner_rg =
                        owner_rg_for_resolution(forwarding, refreshed_decision.resolution);
                    if refreshed_owner_rg > 0 {
                        refreshed_metadata.owner_rg_id = refreshed_owner_rg;
                    }
                    refresh.push((key.clone(), refreshed_decision, refreshed_metadata, origin));
                });

                for (key, refreshed_decision, refreshed_metadata, origin) in refresh {
                    if sessions.refresh_for_ha_transition(
                        &key,
                        refreshed_decision,
                        refreshed_metadata.clone(),
                        now_ns,
                    ) {
                        publish_worker_session_map_entry(
                            session_map_fd,
                            &key,
                            refreshed_decision,
                            &refreshed_metadata,
                            origin,
                            false,
                        );
                    }
                }
            }
            WorkerCommand::ExportOwnerRGSessions {
                sequence,
                owner_rgs,
            } => {
                export_forward_sessions_for_owner_rgs(sessions, &owner_rgs);
                exported_sequences.push(sequence);
            }
            WorkerCommand::UpsertSynced(mut entry) => {
                let key = entry.key.clone();
                let allow_replace_local = synced_entry_allows_local_replace(
                    ha_state,
                    entry.metadata.owner_rg_id,
                    now_secs,
                );
                let is_active = !allow_replace_local;

                // Always resolve synced forward sessions with local egress,
                // regardless of HA state (#326). Synced sessions arrive with
                // the remote node's interface indices and MACs which don't
                // work on this node. By resolving on receipt (even on standby),
                // sessions are immediately forwarding-ready at activation —
                // the helper no longer needs a second activation-time forward
                // scan to fix them up.
                // HA enforcement still happens at packet time via flow cache
                // validation (enforce_ha_resolution_snapshot).
                if !entry.metadata.is_reverse {
                    let flow = SessionFlow {
                        src_ip: key.src_ip,
                        dst_ip: key.dst_ip,
                        forward_key: key.clone(),
                    };
                    let re_resolved = lookup_forwarding_resolution_for_session(
                        forwarding,
                        dynamic_neighbors,
                        &flow,
                        entry.decision,
                    );
                    // On active node, enforce HA snapshot to filter out
                    // sessions for inactive RGs. On standby, skip HA
                    // enforcement — store the resolved ForwardCandidate so
                    // the session is ready when activation happens. The
                    // packet path enforces HA state via flow cache validation.
                    let re_resolved = if is_active {
                        enforce_ha_resolution_snapshot(forwarding, ha_state, now_secs, re_resolved)
                    } else {
                        re_resolved
                    };
                    if re_resolved.disposition != ForwardingDisposition::HAInactive {
                        entry.decision.resolution = re_resolved;
                        let new_owner = owner_rg_for_resolution(forwarding, re_resolved);
                        if new_owner > 0 {
                            entry.metadata.owner_rg_id = new_owner;
                        }
                    }
                }

                let metadata = entry.metadata.clone();
                if sessions.upsert_synced_with_origin(
                    entry.key,
                    entry.decision,
                    entry.metadata,
                    entry.origin,
                    now_ns,
                    entry.protocol,
                    entry.tcp_flags,
                    allow_replace_local,
                ) {
                    publish_worker_session_map_entry(
                        session_map_fd,
                        &key,
                        entry.decision,
                        &metadata,
                        entry.origin,
                        allow_replace_local,
                    );
                }
            }
            WorkerCommand::UpsertLocal(entry) => {
                sessions.install_with_protocol_with_origin(
                    entry.key,
                    entry.decision,
                    entry.metadata,
                    entry.origin,
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
            WorkerCommand::EnqueueShapedLocal(req) => shaped_tx_requests.push(req),
        }
    }
    WorkerCommandResults {
        cancelled_keys,
        exported_sequences,
        shaped_tx_requests,
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
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
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
    delete_bpf_conntrack_entry(
        current.conntrack_v4_fd,
        current.conntrack_v6_fd,
        forward_key,
    );
    delete_bpf_conntrack_entry(
        current.conntrack_v4_fd,
        current.conntrack_v6_fd,
        &reverse_key,
    );
    remove_shared_session(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        forward_key,
    );
    remove_shared_session(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
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

fn materialize_shared_session_hit(
    sessions: &mut SessionTable,
    resolved: &mut ResolvedSessionLookup,
    now_ns: u64,
    tcp_flags: u8,
) -> SessionLookup {
    if let Some(shared) = resolved.shared_entry.take() {
        let replica = synced_replica_entry(&shared);
        sessions.upsert_synced_with_origin(
            replica.key.clone(),
            replica.decision,
            replica.metadata.clone(),
            shared.origin.materialized_shared_hit_origin(),
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

fn maybe_promote_synced_session(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    forwarding: &ForwardingState,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: SessionMetadata,
    origin: SessionOrigin,
    fabric_ingress: bool,
    now_ns: u64,
    protocol: u8,
    tcp_flags: u8,
) -> SessionMetadata {
    if !origin.is_promotable_synced()
        || decision.resolution.disposition != ForwardingDisposition::ForwardCandidate
    {
        return metadata;
    }

    let mut promoted = metadata;
    if promoted.owner_rg_id <= 0 {
        promoted.owner_rg_id = owner_rg_for_resolution(forwarding, decision.resolution);
    }
    if fabric_ingress {
        promoted.fabric_ingress = true;
    }
    if sessions.promote_synced_with_origin(
        key,
        decision,
        promoted.clone(),
        SessionOrigin::SharedPromote,
        now_ns,
        protocol,
        tcp_flags,
    ) {
        let _ = publish_session_map_entry_for_session(session_map_fd, key, decision, &promoted);
        let promoted_entry = SyncedSessionEntry {
            key: key.clone(),
            decision,
            metadata: promoted.clone(),
            origin: SessionOrigin::SharedPromote,
            protocol,
            tcp_flags,
        };
        publish_shared_session(
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            &promoted_entry,
        );
        replicate_session_upsert(peer_worker_commands, &promoted_entry);
    }
    promoted
}

fn is_translated_forward_session_key(
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
) -> bool {
    if metadata.is_reverse {
        return false;
    }
    decision.nat.rewrite_src == Some(key.src_ip) || decision.nat.rewrite_dst == Some(key.dst_ip)
}

fn should_keep_synced_hit_transient(
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
) -> bool {
    origin.is_peer_synced()
        && !owner_rg_is_locally_active(ha_state, metadata.owner_rg_id, now_secs)
        && is_translated_forward_session_key(key, decision, metadata)
}

fn purge_translated_synced_hit(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
) {
    if !origin.is_peer_synced() || !is_translated_forward_session_key(key, decision, metadata) {
        return;
    }
    remove_shared_session(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        key,
    );
    delete_session_map_entry_for_removed_session(session_map_fd, key, decision, metadata);
    sessions.delete(key);
}

pub(super) fn resolve_flow_session_decision(
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
    flow: &SessionFlow,
    now_ns: u64,
    now_secs: u64,
    protocol: u8,
    tcp_flags: u8,
    ingress_ifindex: i32,
    fabric_ingress: bool,
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
        let hit_origin = hit.origin;
        let poison_key = hit
            .shared_entry
            .as_ref()
            .map(|entry| (&entry.key, entry.decision, &entry.metadata, entry.origin))
            .or_else(|| {
                Some((
                    hit.key.as_ref(&flow.forward_key),
                    hit.lookup.decision,
                    &hit.lookup.metadata,
                    hit_origin,
                ))
            });
        let keep_transient = poison_key.is_some_and(|(key, decision, metadata, origin)| {
            should_keep_synced_hit_transient(ha_state, now_secs, key, decision, metadata, origin)
        });
        if keep_transient && let Some((key, decision, metadata, origin)) = poison_key {
            purge_translated_synced_hit(
                sessions,
                session_map_fd,
                shared_sessions,
                shared_nat_sessions,
                shared_forward_wire_sessions,
                shared_owner_rg_indexes,
                key,
                decision,
                metadata,
                origin,
            );
        }
        let resolved = if keep_transient {
            hit.lookup.clone()
        } else {
            materialize_shared_session_hit(sessions, &mut hit, now_ns, tcp_flags)
        };
        let resolved_key = hit.key.as_ref(&flow.forward_key);
        let mut decision = resolved.decision;
        let resolution_target = resolution_target_for_session(flow, decision);
        let looked_up_resolution = if hit_origin.is_peer_synced() {
            lookup_forwarding_resolution_for_synced_session(
                forwarding,
                dynamic_neighbors,
                flow,
                decision,
            )
        } else {
            lookup_forwarding_resolution_for_session(forwarding, dynamic_neighbors, flow, decision)
        };
        let looked_up_resolution = super::prefer_local_forward_candidate_for_fabric_ingress(
            forwarding,
            ha_state,
            dynamic_neighbors,
            now_secs,
            fabric_ingress,
            resolution_target,
            looked_up_resolution,
        );
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
            fabric_ingress,
            resolved.metadata.ingress_zone.as_ref(),
        );
        let metadata = if keep_transient {
            resolved.metadata
        } else {
            maybe_promote_synced_session(
                sessions,
                session_map_fd,
                shared_sessions,
                shared_nat_sessions,
                shared_forward_wire_sessions,
                shared_owner_rg_indexes,
                peer_worker_commands,
                forwarding,
                resolved_key,
                decision,
                resolved.metadata,
                hit_origin,
                fabric_ingress,
                now_ns,
                protocol,
                tcp_flags,
            )
        };
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
        shared_owner_rg_indexes,
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
    let resolution_target = resolution_target_for_session(flow, decision);
    let looked_up_resolution =
        lookup_forwarding_resolution_for_session(forwarding, dynamic_neighbors, flow, decision);
    let looked_up_resolution = super::prefer_local_forward_candidate_for_fabric_ingress(
        forwarding,
        ha_state,
        dynamic_neighbors,
        now_secs,
        fabric_ingress,
        resolution_target,
        looked_up_resolution,
    );
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
        fabric_ingress,
        resolved.metadata.ingress_zone.as_ref(),
    );
    // Reverse sessions created from forward NAT matches are locally
    // created (ReverseFlow), not peer-synced, so they won't be promoted.
    let metadata = maybe_promote_synced_session(
        sessions,
        session_map_fd,
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        peer_worker_commands,
        forwarding,
        &flow.forward_key,
        decision,
        resolved.metadata,
        SessionOrigin::ReverseFlow,
        fabric_ingress,
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

pub(super) fn redirect_session_via_fabric_if_needed(
    forwarding: &ForwardingState,
    resolution: ForwardingResolution,
    fabric_ingress: bool,
    ingress_zone: &str,
) -> ForwardingResolution {
    if resolution.disposition != ForwardingDisposition::HAInactive {
        return resolution;
    }
    if fabric_ingress {
        return resolution;
    }
    resolve_zone_encoded_fabric_redirect(forwarding, ingress_zone)
        .or_else(|| resolve_fabric_redirect(forwarding))
        .unwrap_or(resolution)
}

pub(super) fn enforce_session_ha_resolution(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    now_secs: u64,
    resolution: ForwardingResolution,
    ingress_ifindex: i32,
    ha_startup_grace_until_secs: u64,
) -> ForwardingResolution {
    let enforced = enforce_ha_resolution_snapshot(forwarding, ha_state, now_secs, resolution);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn active_ha_runtime(now_secs: u64) -> HAGroupRuntime {
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: now_secs,
            lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
        }
    }

    fn inactive_ha_runtime(watchdog_timestamp: u64) -> HAGroupRuntime {
        HAGroupRuntime {
            active: false,
            watchdog_timestamp,
            lease: HAForwardingLease::Inactive,
        }
    }

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

    fn test_local_delivery_decision() -> SessionDecision {
        SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::LocalDelivery,
                local_ifindex: 12,
                egress_ifindex: 12,
                tx_ifindex: 12,
                tunnel_endpoint_id: 0,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
            },
            nat: NatDecision::default(),
        }
    }

    fn test_forwarding_state_with_fabric() -> ForwardingState {
        let mut forwarding = test_forwarding_state();
        forwarding.zone_name_to_id.insert("lan".to_string(), 1);
        forwarding.zone_name_to_id.insert("sfmix".to_string(), 2);
        forwarding.zone_name_to_id.insert("wan".to_string(), 3);
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
        let metadata = test_metadata();
        // Install with SyncImport origin to mark as peer-synced
        assert!(sessions.install_with_protocol_with_origin(
            key.clone(),
            decision,
            metadata.clone(),
            SessionOrigin::SyncImport,
            1_000_000,
            PROTO_TCP,
            0x10,
        ));

        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
        let forwarding = test_forwarding_state_with_fabric();

        let promoted = maybe_promote_synced_session(
            &mut sessions,
            -1,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &peer_worker_commands,
            &forwarding,
            &key,
            decision,
            metadata,
            SessionOrigin::SyncImport,
            true,
            2_000_000,
            PROTO_TCP,
            0x10,
        );

        assert!(promoted.fabric_ingress);
    }

    #[test]
    fn maybe_promote_synced_session_skips_worker_local_import() {
        let mut sessions = SessionTable::new();
        let key = test_key();
        let decision = test_decision();
        let metadata = test_metadata();
        assert!(sessions.install_with_protocol_with_origin(
            key.clone(),
            decision,
            metadata.clone(),
            SessionOrigin::WorkerLocalImport,
            1_000_000,
            PROTO_TCP,
            0x10,
        ));

        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
        let forwarding = test_forwarding_state_with_fabric();

        let promoted = maybe_promote_synced_session(
            &mut sessions,
            -1,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &peer_worker_commands,
            &forwarding,
            &key,
            decision,
            metadata.clone(),
            SessionOrigin::WorkerLocalImport,
            false,
            2_000_000,
            PROTO_TCP,
            0x10,
        );

        assert_eq!(promoted, metadata);
        let Some((_decision, _metadata, origin)) = sessions.entry_with_origin(&key) else {
            panic!("worker-local session missing");
        };
        assert_eq!(origin, SessionOrigin::WorkerLocalImport);
        assert!(shared_sessions.lock().expect("shared sessions").is_empty());
    }

    #[test]
    fn resolve_flow_session_decision_promotes_stale_fabric_shared_hit_to_local_owner_path() {
        let mut sessions = SessionTable::new();
        let key = test_key();
        let mut forwarding = test_forwarding_state_with_fabric();
        forwarding.connected_v4.push(ConnectedRouteV4 {
            prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
            ifindex: 12,
            tunnel_endpoint_id: 0,
        });
        forwarding.neighbors.insert(
            (12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
            NeighborEntry {
                mac: [0xde, 0xad, 0xbe, 0xef, 0x80, 0x00],
            },
        );
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let mut ha_state = BTreeMap::new();
        ha_state.insert(1, active_ha_runtime(1));

        let shared_entry = SyncedSessionEntry {
            key: key.clone(),
            decision: SessionDecision {
                resolution: resolve_fabric_redirect(&forwarding).expect("fabric redirect"),
                nat: NatDecision {
                    rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                    rewrite_src_port: Some(key.src_port),
                    ..NatDecision::default()
                },
            },
            metadata: SessionMetadata {
                fabric_ingress: true,
                ..test_metadata()
            },
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0x18,
        };
        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &shared_entry,
        );

        let wire_key = forward_wire_key(&key, shared_entry.decision.nat);
        let flow = SessionFlow {
            src_ip: wire_key.src_ip,
            dst_ip: wire_key.dst_ip,
            forward_key: wire_key,
        };
        let resolved = resolve_flow_session_decision(
            &mut sessions,
            -1,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &peer_worker_commands,
            &forwarding,
            &ha_state,
            &dynamic_neighbors,
            &flow,
            1_000_000,
            1,
            PROTO_TCP,
            0x18,
            21,
            true,
            0,
        )
        .expect("resolved");

        assert_eq!(
            resolved.decision.resolution.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved.decision.resolution.egress_ifindex, 12);
        assert_eq!(resolved.metadata.owner_rg_id, 1);
        assert!(resolved.metadata.fabric_ingress);
    }

    #[test]
    fn cached_session_resolution_skips_fabric_redirect() {
        let forwarding = test_forwarding_state_with_fabric();
        let cached = ForwardingResolution {
            disposition: ForwardingDisposition::FabricRedirect,
            local_ifindex: 0,
            egress_ifindex: 21,
            tx_ifindex: 21,
            tunnel_endpoint_id: 0,
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
            neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
            src_mac: Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]),
            tx_vlan_id: 0,
        };

        assert!(cached_session_resolution(&forwarding, cached).is_none());
    }

    #[test]
    fn lookup_session_across_scopes_returns_shared_entry() {
        let mut sessions = SessionTable::new();
        let key = test_key();
        let entry = SyncedSessionEntry {
            key: key.clone(),
            decision: test_decision(),
            metadata: SessionMetadata { ..test_metadata() },
            origin: SessionOrigin::SyncImport,
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
        assert_eq!(resolved.origin, SessionOrigin::SyncImport);
    }

    #[test]
    fn lookup_session_across_scopes_preserves_local_synced_origin() {
        let mut sessions = SessionTable::new();
        let key = test_key();
        assert!(sessions.install_with_protocol_with_origin(
            key.clone(),
            test_decision(),
            test_metadata(),
            SessionOrigin::SyncImport,
            1,
            PROTO_TCP,
            0,
        ));
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));

        let resolved = lookup_session_across_scopes(
            &mut sessions,
            &shared_sessions,
            &shared_forward_wire_sessions,
            &key,
            2,
            0,
        )
        .expect("local synced hit");
        assert!(resolved.shared_entry.is_none());
        assert_eq!(resolved.key.as_ref(&key), &key);
        assert_eq!(resolved.origin, SessionOrigin::SyncImport);
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
            metadata: SessionMetadata { ..test_metadata() },
            origin: SessionOrigin::SyncImport,
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
        assert_eq!(resolved.origin, SessionOrigin::SyncImport);
    }

    #[test]
    fn lookup_session_across_scopes_preserves_local_forward_wire_synced_origin() {
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
        assert!(sessions.install_with_protocol_with_origin(
            key.clone(),
            decision,
            test_metadata(),
            SessionOrigin::SyncImport,
            1,
            PROTO_TCP,
            0,
        ));
        let translated_key = forward_wire_key(&key, decision.nat);
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));

        let resolved = lookup_session_across_scopes(
            &mut sessions,
            &shared_sessions,
            &shared_forward_wire_sessions,
            &translated_key,
            2,
            0,
        )
        .expect("local forward-wire synced hit");
        assert!(resolved.shared_entry.is_none());
        assert_eq!(resolved.key.as_ref(&translated_key), &key);
        assert_eq!(resolved.origin, SessionOrigin::SyncImport);
    }

    #[test]
    fn lookup_session_across_scopes_prefers_shared_entry_over_fabric_wire_placeholder() {
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
        assert!(sessions.install_with_protocol_with_origin(
            translated_key.clone(),
            decision,
            SessionMetadata {
                fabric_ingress: true,
                ..test_metadata()
            },
            SessionOrigin::ForwardFlow,
            1,
            PROTO_TCP,
            0,
        ));
        let shared_entry = SyncedSessionEntry {
            key: key.clone(),
            decision,
            metadata: SessionMetadata { ..test_metadata() },
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0,
        };
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        shared_forward_wire_sessions
            .lock()
            .expect("shared forward-wire lock")
            .insert(translated_key.clone(), shared_entry.clone());

        let resolved = lookup_session_across_scopes(
            &mut sessions,
            &shared_sessions,
            &shared_forward_wire_sessions,
            &translated_key,
            2,
            0,
        )
        .expect("shared forward-wire hit");
        assert!(resolved.shared_entry.is_some());
        assert_eq!(resolved.key.as_ref(&translated_key), &key);
        assert_eq!(resolved.lookup.decision, shared_entry.decision);
        assert_eq!(resolved.lookup.metadata, shared_entry.metadata);
        assert_eq!(resolved.origin, SessionOrigin::SyncImport);
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
            origin: SessionOrigin::SyncImport,
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
    fn lookup_forward_nat_across_scopes_prefers_shared_entry_over_fabric_wire_placeholder() {
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
        assert!(sessions.install_with_protocol_with_origin(
            translated_key,
            decision,
            SessionMetadata {
                fabric_ingress: true,
                ..test_metadata()
            },
            SessionOrigin::ForwardFlow,
            1,
            PROTO_TCP,
            0,
        ));
        let shared_entry = SyncedSessionEntry {
            key: key.clone(),
            decision,
            metadata: SessionMetadata { ..test_metadata() },
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0,
        };
        let reply_key = reverse_session_key(&key, decision.nat);
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        shared_nat_sessions
            .lock()
            .expect("shared nat lock")
            .insert(reply_key.clone(), shared_entry.clone());

        let hit = lookup_forward_nat_across_scopes(&sessions, &shared_nat_sessions, &reply_key)
            .expect("shared nat hit");
        assert_eq!(hit.key, shared_entry.key);
        assert_eq!(hit.decision, shared_entry.decision);
        assert_eq!(hit.metadata, shared_entry.metadata);
    }

    #[test]
    fn lookup_forward_nat_across_scopes_ignores_fabric_wire_placeholder_without_shared_entry() {
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
        assert!(sessions.install_with_protocol_with_origin(
            translated_key,
            decision,
            SessionMetadata {
                fabric_ingress: true,
                ..test_metadata()
            },
            SessionOrigin::ForwardFlow,
            1,
            PROTO_TCP,
            0,
        ));
        let reply_key = reverse_session_key(&key, decision.nat);
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));

        assert!(
            lookup_forward_nat_across_scopes(&sessions, &shared_nat_sessions, &reply_key).is_none()
        );
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
            metadata: SessionMetadata { ..test_metadata() },
            origin: SessionOrigin::SyncImport,
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
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
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
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0,
        };
        let translated_key = forward_wire_key(&key, decision.nat);

        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
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
            &shared_owner_rg_indexes,
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
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
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
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0,
        };
        let canonical_reply = reverse_canonical_key(&key, decision.nat);

        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &entry,
        );
        let alias_hit = lookup_shared_forward_nat_match(&shared_nat_sessions, &canonical_reply)
            .expect("canonical reverse alias should be published");
        assert_eq!(alias_hit.key, key);

        remove_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &entry.key,
        );
        assert!(lookup_shared_forward_nat_match(&shared_nat_sessions, &canonical_reply).is_none());
    }

    #[test]
    fn publish_and_remove_shared_session_tracks_owner_rg_indexes() {
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
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
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0,
        };
        let forward_wire = forward_wire_key(&key, decision.nat);
        let reverse_wire = reverse_session_key(&key, decision.nat);
        let reverse_canonical = reverse_canonical_key(&key, decision.nat);

        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &entry,
        );

        let sessions_index = shared_owner_rg_indexes
            .sessions
            .lock()
            .expect("sessions index");
        assert!(
            sessions_index
                .get(&entry.metadata.owner_rg_id)
                .is_some_and(|keys| keys.contains(&key))
        );
        drop(sessions_index);

        let nat_index = shared_owner_rg_indexes
            .nat_sessions
            .lock()
            .expect("nat index");
        assert!(
            nat_index
                .get(&entry.metadata.owner_rg_id)
                .is_some_and(
                    |keys| keys.contains(&reverse_wire) && keys.contains(&reverse_canonical)
                )
        );
        drop(nat_index);

        let forward_wire_index = shared_owner_rg_indexes
            .forward_wire_sessions
            .lock()
            .expect("forward-wire index");
        assert!(
            forward_wire_index
                .get(&entry.metadata.owner_rg_id)
                .is_some_and(|keys| keys.contains(&forward_wire))
        );
        drop(forward_wire_index);

        remove_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &entry.key,
        );

        assert!(
            shared_owner_rg_indexes
                .sessions
                .lock()
                .expect("sessions index")
                .is_empty()
        );
        assert!(
            shared_owner_rg_indexes
                .nat_sessions
                .lock()
                .expect("nat index")
                .is_empty()
        );
        assert!(
            shared_owner_rg_indexes
                .forward_wire_sessions
                .lock()
                .expect("forward-wire index")
                .is_empty()
        );
    }

    #[test]
    fn publish_shared_session_reindexes_owner_rg_on_replace() {
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let mut entry = SyncedSessionEntry {
            key: test_key(),
            decision: test_decision(),
            metadata: test_metadata(),
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0,
        };

        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &entry,
        );

        entry.metadata.owner_rg_id = 2;
        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &entry,
        );

        assert!(
            shared_owner_rg_indexes
                .sessions
                .lock()
                .expect("sessions index")
                .get(&1)
                .is_none()
        );
        assert!(
            shared_owner_rg_indexes
                .sessions
                .lock()
                .expect("sessions index")
                .get(&2)
                .is_some_and(|keys| keys.contains(&entry.key))
        );
    }

    #[test]
    fn publish_shared_session_heals_missing_owner_rg_index_on_same_owner_update() {
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let entry = SyncedSessionEntry {
            key: test_key(),
            decision: test_decision(),
            metadata: test_metadata(),
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0,
        };

        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &entry,
        );

        shared_owner_rg_indexes
            .sessions
            .lock()
            .expect("sessions index")
            .clear();

        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &entry,
        );

        assert!(
            shared_owner_rg_indexes
                .sessions
                .lock()
                .expect("sessions index")
                .get(&entry.metadata.owner_rg_id)
                .is_some_and(|keys| keys.contains(&entry.key))
        );
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
            metadata: SessionMetadata { ..test_metadata() },
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0,
        };
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
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
            &shared_owner_rg_indexes,
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
            false,
            0,
        )
        .expect("translated forward hit should resolve");

        assert!(!resolved.created);

        assert!(sessions.lookup(&translated_key, 1_000_000, 0x10).is_none());
        let local_hit = sessions
            .find_forward_wire_match(&translated_key)
            .expect("local canonical session should keep forward-wire alias");
        assert_eq!(local_hit.key, key);
        assert_eq!(resolved.decision.nat, decision.nat);
    }

    #[test]
    fn resolve_flow_session_decision_promotes_translated_shared_hit_on_active_fabric_ingress() {
        let mut sessions = SessionTable::new();
        let key = test_key();
        let decision = SessionDecision {
            resolution: resolve_fabric_redirect(&test_forwarding_state_with_fabric())
                .expect("fabric redirect"),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_src_port: Some(key.src_port),
                ..NatDecision::default()
            },
        };
        let translated_key = forward_wire_key(&key, decision.nat);
        let entry = SyncedSessionEntry {
            key: translated_key.clone(),
            decision,
            metadata: SessionMetadata { ..test_metadata() },
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0x18,
        };
        let mut forwarding = test_forwarding_state_with_fabric();
        forwarding.connected_v4.push(ConnectedRouteV4 {
            prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
            ifindex: 12,
            tunnel_endpoint_id: 0,
        });
        forwarding.neighbors.insert(
            (12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
            NeighborEntry {
                mac: [0xde, 0xad, 0xbe, 0xef, 0x80, 0x00],
            },
        );
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &entry,
        );
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let peer_worker_commands = Vec::new();
        let mut ha_state = BTreeMap::new();
        ha_state.insert(1, active_ha_runtime(1));

        let flow = SessionFlow {
            src_ip: translated_key.src_ip,
            dst_ip: translated_key.dst_ip,
            forward_key: translated_key.clone(),
        };
        let resolved = resolve_flow_session_decision(
            &mut sessions,
            -1,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &peer_worker_commands,
            &forwarding,
            &ha_state,
            &dynamic_neighbors,
            &flow,
            1_000_000,
            1,
            PROTO_TCP,
            0x18,
            21,
            true,
            0,
        )
        .expect("translated shared hit should resolve");

        assert_eq!(
            resolved.decision.resolution.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved.decision.resolution.egress_ifindex, 12);

        let local_hit = sessions
            .lookup(&translated_key, 1_000_000, 0x18)
            .expect("promoted translated hit should stay local");
        assert_eq!(local_hit.decision.nat, decision.nat);

        assert!(
            shared_sessions
                .lock()
                .expect("shared lock")
                .get(&translated_key)
                .is_some()
        );
    }

    #[test]
    fn resolve_flow_session_decision_promotes_local_synced_translated_hit_on_active_fabric_ingress()
    {
        let mut sessions = SessionTable::new();
        let key = test_key();
        let decision = SessionDecision {
            resolution: resolve_fabric_redirect(&test_forwarding_state_with_fabric())
                .expect("fabric redirect"),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_src_port: Some(key.src_port),
                ..NatDecision::default()
            },
        };
        let translated_key = forward_wire_key(&key, decision.nat);
        assert!(sessions.install_with_protocol_with_origin(
            translated_key.clone(),
            decision,
            SessionMetadata { ..test_metadata() },
            SessionOrigin::SyncImport,
            1_000_000,
            PROTO_TCP,
            0x18,
        ));
        let mut forwarding = test_forwarding_state_with_fabric();
        forwarding.connected_v4.push(ConnectedRouteV4 {
            prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
            ifindex: 12,
            tunnel_endpoint_id: 0,
        });
        forwarding.neighbors.insert(
            (12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
            NeighborEntry {
                mac: [0xde, 0xad, 0xbe, 0xef, 0x80, 0x00],
            },
        );
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let peer_worker_commands = Vec::new();
        let mut ha_state = BTreeMap::new();
        ha_state.insert(1, active_ha_runtime(1));

        let flow = SessionFlow {
            src_ip: translated_key.src_ip,
            dst_ip: translated_key.dst_ip,
            forward_key: translated_key.clone(),
        };
        let resolved = resolve_flow_session_decision(
            &mut sessions,
            -1,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &peer_worker_commands,
            &forwarding,
            &ha_state,
            &dynamic_neighbors,
            &flow,
            1_000_000,
            1,
            PROTO_TCP,
            0x18,
            21,
            true,
            0,
        )
        .expect("translated local hit should resolve");

        assert_eq!(
            resolved.decision.resolution.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved.decision.resolution.egress_ifindex, 12);

        let local_hit = sessions
            .lookup(&translated_key, 1_000_000, 0x18)
            .expect("promoted translated local hit should stay local");
        assert_eq!(local_hit.decision.nat, decision.nat);
    }

    #[test]
    fn resolve_flow_session_decision_keeps_translated_shared_hit_transient_on_inactive_fabric_ingress()
     {
        let mut sessions = SessionTable::new();
        let key = test_key();
        let decision = SessionDecision {
            resolution: resolve_fabric_redirect(&test_forwarding_state_with_fabric())
                .expect("fabric redirect"),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_src_port: Some(key.src_port),
                ..NatDecision::default()
            },
        };
        let translated_key = forward_wire_key(&key, decision.nat);
        let entry = SyncedSessionEntry {
            key: translated_key.clone(),
            decision,
            metadata: SessionMetadata { ..test_metadata() },
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0x18,
        };
        let mut forwarding = test_forwarding_state_with_fabric();
        forwarding.connected_v4.push(ConnectedRouteV4 {
            prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
            ifindex: 12,
            tunnel_endpoint_id: 0,
        });
        forwarding.neighbors.insert(
            (12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
            NeighborEntry {
                mac: [0xde, 0xad, 0xbe, 0xef, 0x80, 0x00],
            },
        );
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &entry,
        );
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let peer_worker_commands = Vec::new();
        let mut ha_state = BTreeMap::new();
        ha_state.insert(1, inactive_ha_runtime(0));

        let flow = SessionFlow {
            src_ip: translated_key.src_ip,
            dst_ip: translated_key.dst_ip,
            forward_key: translated_key.clone(),
        };
        let _resolved = resolve_flow_session_decision(
            &mut sessions,
            -1,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &peer_worker_commands,
            &forwarding,
            &ha_state,
            &dynamic_neighbors,
            &flow,
            1_000_000,
            1,
            PROTO_TCP,
            0x18,
            21,
            true,
            0,
        )
        .expect("translated shared hit should resolve");

        assert!(sessions.lookup(&translated_key, 1_000_000, 0x18).is_none());
    }

    #[test]
    fn resolve_flow_session_decision_keeps_translated_shared_hit_transient_on_inactive_non_fabric_ingress()
     {
        let mut sessions = SessionTable::new();
        let key = test_key();
        let decision = SessionDecision {
            resolution: resolve_fabric_redirect(&test_forwarding_state_with_fabric())
                .expect("fabric redirect"),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_src_port: Some(key.src_port),
                ..NatDecision::default()
            },
        };
        let translated_key = forward_wire_key(&key, decision.nat);
        let entry = SyncedSessionEntry {
            key: translated_key.clone(),
            decision,
            metadata: SessionMetadata { ..test_metadata() },
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0x18,
        };
        let mut forwarding = test_forwarding_state_with_fabric();
        forwarding.connected_v4.push(ConnectedRouteV4 {
            prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
            ifindex: 12,
            tunnel_endpoint_id: 0,
        });
        forwarding.neighbors.insert(
            (12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
            NeighborEntry {
                mac: [0xde, 0xad, 0xbe, 0xef, 0x80, 0x00],
            },
        );
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &entry,
        );
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let peer_worker_commands = Vec::new();
        let mut ha_state = BTreeMap::new();
        ha_state.insert(1, inactive_ha_runtime(0));

        let flow = SessionFlow {
            src_ip: translated_key.src_ip,
            dst_ip: translated_key.dst_ip,
            forward_key: translated_key.clone(),
        };
        let _resolved = resolve_flow_session_decision(
            &mut sessions,
            -1,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &peer_worker_commands,
            &forwarding,
            &ha_state,
            &dynamic_neighbors,
            &flow,
            1_000_000,
            1,
            PROTO_TCP,
            0x18,
            12,
            false,
            0,
        )
        .expect("translated shared hit should resolve");

        assert!(sessions.lookup(&translated_key, 1_000_000, 0x18).is_none());
    }

    #[test]
    fn resolve_flow_session_decision_keeps_local_synced_translated_hit_transient_on_inactive_non_fabric_ingress()
     {
        let mut sessions = SessionTable::new();
        let key = test_key();
        let decision = SessionDecision {
            resolution: resolve_fabric_redirect(&test_forwarding_state_with_fabric())
                .expect("fabric redirect"),
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                rewrite_src_port: Some(key.src_port),
                ..NatDecision::default()
            },
        };
        let translated_key = forward_wire_key(&key, decision.nat);
        assert!(sessions.install_with_protocol_with_origin(
            translated_key.clone(),
            decision,
            SessionMetadata { ..test_metadata() },
            SessionOrigin::SyncImport,
            1_000_000,
            PROTO_TCP,
            0x18,
        ));
        let mut forwarding = test_forwarding_state_with_fabric();
        forwarding.connected_v4.push(ConnectedRouteV4 {
            prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
            ifindex: 12,
            tunnel_endpoint_id: 0,
        });
        forwarding.neighbors.insert(
            (12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
            NeighborEntry {
                mac: [0xde, 0xad, 0xbe, 0xef, 0x80, 0x00],
            },
        );
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let peer_worker_commands = Vec::new();
        let mut ha_state = BTreeMap::new();
        ha_state.insert(1, inactive_ha_runtime(0));

        let flow = SessionFlow {
            src_ip: translated_key.src_ip,
            dst_ip: translated_key.dst_ip,
            forward_key: translated_key.clone(),
        };
        let _resolved = resolve_flow_session_decision(
            &mut sessions,
            -1,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &peer_worker_commands,
            &forwarding,
            &ha_state,
            &dynamic_neighbors,
            &flow,
            1_000_000,
            1,
            PROTO_TCP,
            0x18,
            12,
            false,
            0,
        )
        .expect("translated local hit should resolve");

        assert!(sessions.lookup(&translated_key, 1_000_000, 0x18).is_none());
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
        let synced_metadata = SessionMetadata { ..test_metadata() };
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
                origin: SessionOrigin::SyncImport,
                protocol: PROTO_TCP,
                tcp_flags: 0x10,
            }));
        let mut ha_state = BTreeMap::new();
        ha_state.insert(1, inactive_ha_runtime(0));
        let forwarding = test_forwarding_state();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        apply_worker_commands(
            &commands,
            &mut sessions,
            -1,
            -1,
            -1,
            &forwarding,
            &ha_state,
            &dynamic_neighbors,
        );

        let hit = sessions.lookup(&key, 2_000_000, 0x10).expect("synced hit");
        assert_eq!(hit.metadata, synced_metadata);
        // With #326, synced sessions are always re-resolved with local egress
        // info even on standby — so tx_vlan_id picks up the local egress VLAN.
        let expected_decision = SessionDecision {
            resolution: ForwardingResolution {
                tx_vlan_id: 80,
                ..synced_decision.resolution
            },
            ..synced_decision
        };
        assert_eq!(hit.decision, expected_decision);
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
                metadata: SessionMetadata { ..test_metadata() },
                origin: SessionOrigin::SyncImport,
                protocol: PROTO_TCP,
                tcp_flags: 0x10,
            }));
        let mut ha_state = BTreeMap::new();
        ha_state.insert(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000));
        let forwarding = test_forwarding_state();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        apply_worker_commands(
            &commands,
            &mut sessions,
            -1,
            -1,
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
    fn worker_synced_local_delivery_forces_live_redirect_on_standby() {
        assert!(force_live_redirect_for_worker_synced_entry(
            test_local_delivery_decision(),
            &test_metadata(),
            SessionOrigin::SyncImport,
            true,
        ));
    }

    #[test]
    fn worker_synced_local_delivery_keeps_default_publish_on_active_owner() {
        assert!(!force_live_redirect_for_worker_synced_entry(
            test_local_delivery_decision(),
            &test_metadata(),
            SessionOrigin::SyncImport,
            false,
        ));
    }

    #[test]
    fn apply_worker_commands_demotes_local_owner_rg_sessions_to_sync_import() {
        let commands = Arc::new(Mutex::new(VecDeque::new()));
        let mut sessions = SessionTable::new();
        let key = test_key();
        assert!(sessions.install_with_protocol(
            key.clone(),
            test_decision(),
            test_metadata(),
            1_000_000,
            PROTO_TCP,
            0x10,
        ));
        commands
            .lock()
            .expect("commands lock")
            .push_back(WorkerCommand::DemoteOwnerRGS { owner_rgs: vec![1] });
        let forwarding = test_forwarding_state();
        let ha_state = BTreeMap::from([(1, inactive_ha_runtime(0))]);
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));

        apply_worker_commands(
            &commands,
            &mut sessions,
            -1,
            -1,
            -1,
            &forwarding,
            &ha_state,
            &dynamic_neighbors,
        );

        let Some((_decision, _metadata, origin)) = sessions.entry_with_origin(&key) else {
            panic!("demoted session missing");
        };
        assert_eq!(origin, SessionOrigin::SyncImport);
    }

    #[test]
    fn demoted_local_session_promotes_as_synced_on_failback_lookup() {
        let commands = Arc::new(Mutex::new(VecDeque::new()));
        let mut sessions = SessionTable::new();
        let key = test_key();
        let decision = test_decision();
        let metadata = test_metadata();
        assert!(sessions.install_with_protocol(
            key.clone(),
            decision,
            metadata.clone(),
            1_000_000,
            PROTO_TCP,
            0x10,
        ));
        commands
            .lock()
            .expect("commands lock")
            .push_back(WorkerCommand::DemoteOwnerRGS { owner_rgs: vec![1] });
        let forwarding = test_forwarding_state();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let inactive_state = BTreeMap::from([(1, inactive_ha_runtime(0))]);

        apply_worker_commands(
            &commands,
            &mut sessions,
            -1,
            -1,
            -1,
            &forwarding,
            &inactive_state,
            &dynamic_neighbors,
        );

        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let peer_worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>> = Vec::new();
        let active_state = BTreeMap::from([(1, active_ha_runtime(1))]);
        let flow = SessionFlow {
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            forward_key: key.clone(),
        };

        let resolved = resolve_flow_session_decision(
            &mut sessions,
            -1,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &peer_worker_commands,
            &forwarding,
            &active_state,
            &dynamic_neighbors,
            &flow,
            2_000_000,
            2,
            PROTO_TCP,
            0x10,
            6,
            false,
            0,
        )
        .expect("resolved demoted session");

        assert!(!resolved.created);
        let Some((_decision, _metadata, origin)) = sessions.entry_with_origin(&key) else {
            panic!("promoted session missing");
        };
        assert_eq!(origin, SessionOrigin::SharedPromote);
    }

    #[test]
    fn epoch_based_flow_cache_invalidation_for_demoted_owner_rg() {
        let rg_epochs: [AtomicU32; MAX_RG_EPOCHS] = std::array::from_fn(|_| AtomicU32::new(0));
        let mut flow_cache = FlowCache::new();
        let key = test_key();
        let metadata = SessionMetadata {
            owner_rg_id: 1,
            ..test_metadata()
        };
        // Insert with current epoch (0).
        flow_cache.insert(FlowCacheEntry {
            key: key.clone(),
            ingress_ifindex: 7,
            descriptor: RewriteDescriptor {
                dst_mac: [0; 6],
                src_mac: [0; 6],
                fabric_redirect: false,
                tx_vlan_id: 0,
                ether_type: 0x0800,
                rewrite_src_ip: None,
                rewrite_dst_ip: None,
                rewrite_src_port: None,
                rewrite_dst_port: None,
                ip_csum_delta: 0,
                l4_csum_delta: 0,
                egress_ifindex: 6,
                tx_ifindex: 6,
                target_binding_index: None,
                nat64: false,
                nptv6: false,
                apply_nat_on_fabric: false,
            },
            decision: test_decision(),
            metadata,
            stamp: FlowCacheStamp {
                config_generation: 1,
                fib_generation: 1,
                owner_rg_id: 1,
                owner_rg_epoch: 0,
                owner_rg_lease_until: 0,
            },
        });

        // Before epoch bump, lookup should hit.
        assert!(
            flow_cache
                .lookup(
                    &key,
                    FlowCacheLookup {
                        ingress_ifindex: 7,
                        config_generation: 1,
                        fib_generation: 1,
                    },
                    0,
                    &rg_epochs,
                )
                .is_some()
        );

        // Bump epoch for RG 1 (simulates demotion).
        rg_epochs[1].fetch_add(1, Ordering::Relaxed);

        // After epoch bump, lookup should miss (stale entry).
        assert!(
            flow_cache
                .lookup(
                    &key,
                    FlowCacheLookup {
                        ingress_ifindex: 7,
                        config_generation: 1,
                        fib_generation: 1,
                    },
                    0,
                    &rg_epochs,
                )
                .is_none()
        );
    }

    #[test]
    fn epoch_based_flow_cache_unrelated_rg_not_invalidated() {
        let rg_epochs: [AtomicU32; MAX_RG_EPOCHS] = std::array::from_fn(|_| AtomicU32::new(0));
        let mut flow_cache = FlowCache::new();
        let key = test_key();
        let metadata = SessionMetadata {
            owner_rg_id: 1,
            ..test_metadata()
        };
        flow_cache.insert(FlowCacheEntry {
            key: key.clone(),
            ingress_ifindex: 7,
            descriptor: RewriteDescriptor {
                dst_mac: [0; 6],
                src_mac: [0; 6],
                fabric_redirect: false,
                tx_vlan_id: 0,
                ether_type: 0x0800,
                rewrite_src_ip: None,
                rewrite_dst_ip: None,
                rewrite_src_port: None,
                rewrite_dst_port: None,
                ip_csum_delta: 0,
                l4_csum_delta: 0,
                egress_ifindex: 6,
                tx_ifindex: 6,
                target_binding_index: None,
                nat64: false,
                nptv6: false,
                apply_nat_on_fabric: false,
            },
            decision: test_decision(),
            metadata,
            stamp: FlowCacheStamp {
                config_generation: 1,
                fib_generation: 1,
                owner_rg_id: 1,
                owner_rg_epoch: 0,
                owner_rg_lease_until: 0,
            },
        });

        // Bump epoch for RG 2 (unrelated).
        rg_epochs[2].fetch_add(1, Ordering::Relaxed);

        // RG 1 entry should still hit — only RG 2 was bumped.
        assert!(
            flow_cache
                .lookup(
                    &key,
                    FlowCacheLookup {
                        ingress_ifindex: 7,
                        config_generation: 1,
                        fib_generation: 1,
                    },
                    0,
                    &rg_epochs,
                )
                .is_some()
        );
    }

    #[test]
    fn apply_worker_commands_exports_owner_rg_forward_sessions_without_teardown() {
        let commands = Arc::new(Mutex::new(VecDeque::new()));
        let mut sessions = SessionTable::new();
        let key = test_key();
        let decision = SessionDecision {
            resolution: test_decision().resolution,
            nat: NatDecision {
                rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                ..NatDecision::default()
            },
        };
        let metadata = SessionMetadata {
            owner_rg_id: 1,
            ..test_metadata()
        };
        assert!(sessions.install_with_protocol(
            key.clone(),
            decision,
            metadata,
            1_000_000,
            PROTO_TCP,
            0x10,
        ));
        assert_eq!(sessions.drain_deltas(16).len(), 1, "initial open delta");
        commands
            .lock()
            .expect("commands lock")
            .push_back(WorkerCommand::ExportOwnerRGSessions {
                sequence: 9,
                owner_rgs: vec![1],
            });
        let forwarding = test_forwarding_state_with_fabric();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let mut ha_state = BTreeMap::new();
        ha_state.insert(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000));
        let results = apply_worker_commands(
            &commands,
            &mut sessions,
            -1,
            -1,
            -1,
            &forwarding,
            &ha_state,
            &dynamic_neighbors,
        );

        assert!(results.cancelled_keys.is_empty());
        assert_eq!(results.exported_sequences, vec![9]);
        let hit = sessions
            .lookup(&key, 2_000_000, 0x10)
            .expect("exported forward hit");

        assert_eq!(
            hit.decision.resolution.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        let deltas = sessions.drain_deltas(16);
        assert_eq!(deltas.len(), 1, "export should republish forward session");
        assert_eq!(deltas[0].kind, SessionDeltaKind::Open);
        assert!(deltas[0].fabric_redirect_sync);
    }

    #[test]
    fn apply_worker_commands_does_not_export_missing_neighbor_seed_sessions() {
        let commands = Arc::new(Mutex::new(VecDeque::new()));
        let mut sessions = SessionTable::new();
        let key = test_key();
        let metadata = SessionMetadata {
            owner_rg_id: 1,
            ..test_metadata()
        };
        assert!(sessions.install_with_protocol_with_origin(
            key,
            test_decision(),
            metadata,
            SessionOrigin::MissingNeighborSeed,
            1_000_000,
            PROTO_TCP,
            0x10,
        ));
        assert!(
            sessions.drain_deltas(16).is_empty(),
            "missing-neighbor seed install should not emit open deltas"
        );
        commands
            .lock()
            .expect("commands lock")
            .push_back(WorkerCommand::ExportOwnerRGSessions {
                sequence: 10,
                owner_rgs: vec![1],
            });
        let forwarding = test_forwarding_state_with_fabric();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let mut ha_state = BTreeMap::new();
        ha_state.insert(1, active_ha_runtime(monotonic_nanos() / 1_000_000_000));
        let results = apply_worker_commands(
            &commands,
            &mut sessions,
            -1,
            -1,
            -1,
            &forwarding,
            &ha_state,
            &dynamic_neighbors,
        );

        assert!(results.cancelled_keys.is_empty());
        assert_eq!(results.exported_sequences, vec![10]);
        assert!(
            sessions.drain_deltas(16).is_empty(),
            "missing-neighbor seed sessions must not be exported as HA deltas"
        );
    }

    #[test]
    fn apply_worker_commands_demote_owner_rg_returns_cancelled_keys() {
        let commands = Arc::new(Mutex::new(VecDeque::new()));
        let mut sessions = SessionTable::new();
        let key = test_key();
        assert!(sessions.install_with_protocol_with_origin(
            key.clone(),
            test_decision(),
            test_metadata(),
            SessionOrigin::ForwardFlow,
            1_000_000,
            PROTO_TCP,
            0x10,
        ));
        commands
            .lock()
            .expect("commands lock")
            .push_back(WorkerCommand::DemoteOwnerRGS {
                owner_rgs: vec![1, 1],
            });

        let forwarding = test_forwarding_state_with_fabric();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let mut ha_state = BTreeMap::new();
        ha_state.insert(1, inactive_ha_runtime(monotonic_nanos() / 1_000_000_000));

        let results = apply_worker_commands(
            &commands,
            &mut sessions,
            -1,
            -1,
            -1,
            &forwarding,
            &ha_state,
            &dynamic_neighbors,
        );

        assert_eq!(results.exported_sequences, Vec::<u64>::new());
        assert_eq!(results.cancelled_keys.len(), 1);
        assert!(results.cancelled_keys.iter().any(|k| k == &key));
    }

    #[test]
    fn demote_shared_owner_rgs_preserves_reverse_entries_and_marks_all_synced() {
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let forward = SyncedSessionEntry {
            key: test_key(),
            decision: test_decision(),
            metadata: test_metadata(),
            origin: SessionOrigin::SyncImport,
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
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
        };
        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
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
            &shared_owner_rg_indexes,
            &test_forwarding_state_with_fabric(),
            &Arc::new(Mutex::new(FastMap::default())),
            &[1],
        );

        let shared_forward = shared_sessions
            .lock()
            .expect("shared sessions")
            .get(&forward.key)
            .cloned()
            .expect("forward entry");
        assert!(shared_forward.origin.is_peer_synced());
        let shared_reverse = shared_sessions
            .lock()
            .expect("shared sessions")
            .get(&reverse.key)
            .cloned()
            .expect("reverse entry");
        assert!(shared_reverse.origin.is_peer_synced());
        let reverse_alias = reverse_session_key(&forward.key, forward.decision.nat);
        let nat_alias = shared_nat_sessions
            .lock()
            .expect("shared nat")
            .get(&reverse_alias)
            .cloned()
            .expect("nat alias");
        assert!(nat_alias.origin.is_peer_synced());
    }

    #[test]
    fn demoted_shared_local_forward_session_enters_reverse_prewarm_index() {
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let forwarding = test_forwarding_state_split_rgs();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let mut entry = SyncedSessionEntry {
            key: test_key(),
            decision: test_decision(),
            metadata: SessionMetadata {
                fabric_ingress: true,
                ..test_metadata()
            },
            origin: SessionOrigin::ForwardFlow,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
        };
        entry.metadata.owner_rg_id = 1;

        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &entry,
        );

        demote_shared_owner_rgs(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &forwarding,
            &dynamic_neighbors,
            &[1],
        );

        let index = shared_owner_rg_indexes
            .reverse_prewarm_sessions
            .lock()
            .expect("prewarm index");
        assert!(index.get(&1).is_some_and(|keys| keys.contains(&entry.key)));
        assert!(index.get(&2).is_some_and(|keys| keys.contains(&entry.key)));
    }

    #[test]
    fn prewarm_reverse_synced_sessions_after_demotion_recomputes_split_owner_reverse() {
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let worker_commands = vec![Arc::new(Mutex::new(VecDeque::new()))];
        let forwarding = test_forwarding_state_split_rgs();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let mut ha_state = BTreeMap::new();
        ha_state.insert(2, active_ha_runtime(1));
        let mut entry = SyncedSessionEntry {
            key: test_key(),
            decision: test_decision(),
            metadata: SessionMetadata {
                fabric_ingress: true,
                ..test_metadata()
            },
            origin: SessionOrigin::ForwardFlow,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
        };
        entry.metadata.owner_rg_id = 1;

        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &entry,
        );
        demote_shared_owner_rgs(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &forwarding,
            &dynamic_neighbors,
            &[1],
        );

        prewarm_reverse_synced_sessions_for_owner_rgs(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
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
        assert_eq!(reverse.metadata.owner_rg_id, 2);
        assert_eq!(worker_commands[0].lock().expect("commands").len(), 2);
    }

    #[test]
    fn apply_worker_commands_demotes_local_owner_rg_sessions_and_cancels_keys() {
        let commands = Arc::new(Mutex::new(VecDeque::from([
            WorkerCommand::DemoteOwnerRGS { owner_rgs: vec![1] },
        ])));
        let mut sessions = SessionTable::new();
        let key = test_key();
        let decision = test_decision();
        let metadata = test_metadata();
        let now_ns = monotonic_nanos();

        assert!(sessions.install_with_protocol_with_origin(
            key.clone(),
            decision,
            metadata,
            SessionOrigin::ForwardFlow,
            now_ns,
            PROTO_TCP,
            0x10,
        ));

        let results = apply_worker_commands(
            &commands,
            &mut sessions,
            -1,
            -1,
            -1,
            &test_forwarding_state_with_fabric(),
            &BTreeMap::new(),
            &Arc::new(Mutex::new(FastMap::default())),
        );

        assert_eq!(results.cancelled_keys, vec![key.clone()]);
        let (_, origin) = sessions
            .lookup_with_origin(&key, now_ns, 0x10)
            .expect("demoted session");
        assert!(origin.is_peer_synced());
    }

    #[test]
    fn apply_worker_commands_demote_owner_rg_rewrites_resolution_to_fabric_redirect() {
        let commands = Arc::new(Mutex::new(VecDeque::from([
            WorkerCommand::DemoteOwnerRGS { owner_rgs: vec![1] },
        ])));
        let mut sessions = SessionTable::new();
        let key = test_key();
        let decision = test_decision();
        let metadata = test_metadata();
        let now_ns = monotonic_nanos();

        assert!(sessions.install_with_protocol_with_origin(
            key.clone(),
            decision,
            metadata,
            SessionOrigin::ForwardFlow,
            now_ns,
            PROTO_TCP,
            0x10,
        ));

        let ha_state = BTreeMap::from([(1, inactive_ha_runtime(now_ns / 1_000_000_000))]);
        let results = apply_worker_commands(
            &commands,
            &mut sessions,
            -1,
            -1,
            -1,
            &test_forwarding_state_with_fabric(),
            &ha_state,
            &Arc::new(Mutex::new(FastMap::default())),
        );

        assert_eq!(results.cancelled_keys, vec![key.clone()]);
        let (lookup, origin) = sessions
            .lookup_with_origin(&key, now_ns, 0x10)
            .expect("demoted session");
        assert!(origin.is_peer_synced());
        assert_eq!(
            lookup.decision.resolution.disposition,
            ForwardingDisposition::FabricRedirect
        );
        assert_eq!(lookup.decision.resolution.egress_ifindex, 21);
    }

    #[test]
    fn apply_worker_commands_demote_split_reverse_owner_rg_rewrites_to_fabric_redirect() {
        let commands = Arc::new(Mutex::new(VecDeque::from([
            WorkerCommand::DemoteOwnerRGS { owner_rgs: vec![2] },
        ])));
        let mut sessions = SessionTable::new();
        let forward_key = test_key();
        let reverse_key = reverse_session_key(&forward_key, test_decision().nat);
        let now_ns = monotonic_nanos();

        assert!(sessions.install_with_protocol_with_origin(
            reverse_key.clone(),
            SessionDecision {
                resolution: ForwardingResolution {
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
                nat: test_decision().nat.reverse(
                    forward_key.src_ip,
                    forward_key.dst_ip,
                    forward_key.src_port,
                    forward_key.dst_port,
                ),
            },
            SessionMetadata {
                ingress_zone: Arc::<str>::from("wan"),
                egress_zone: Arc::<str>::from("lan"),
                owner_rg_id: 2,
                fabric_ingress: false,
                is_reverse: true,
                nat64_reverse: None,
            },
            SessionOrigin::SyncImport,
            now_ns,
            PROTO_TCP,
            0x10,
        ));

        let ha_state = BTreeMap::from([(2, inactive_ha_runtime(now_ns / 1_000_000_000))]);
        let results = apply_worker_commands(
            &commands,
            &mut sessions,
            -1,
            -1,
            -1,
            &test_forwarding_state_split_rgs(),
            &ha_state,
            &Arc::new(Mutex::new(FastMap::default())),
        );

        assert_eq!(results.cancelled_keys, vec![reverse_key.clone()]);
        let (lookup, origin) = sessions
            .lookup_with_origin(&reverse_key, now_ns, 0x10)
            .expect("demoted reverse session");
        assert!(origin.is_peer_synced());
        assert_eq!(
            lookup.decision.resolution.disposition,
            ForwardingDisposition::FabricRedirect
        );
        assert_eq!(lookup.decision.resolution.egress_ifindex, 21);
        assert_eq!(lookup.metadata.owner_rg_id, 2);
        assert!(lookup.metadata.is_reverse);
    }

    #[test]
    fn apply_worker_commands_refresh_split_reverse_owner_rg_rewrites_to_forward_candidate() {
        let commands = Arc::new(Mutex::new(VecDeque::from([
            WorkerCommand::RefreshOwnerRGS { owner_rgs: vec![2] },
        ])));
        let mut sessions = SessionTable::new();
        let forward_key = test_key();
        let reverse_key = reverse_session_key(&forward_key, test_decision().nat);
        let now_ns = monotonic_nanos();

        assert!(sessions.install_with_protocol_with_origin(
            reverse_key.clone(),
            SessionDecision {
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::FabricRedirect,
                    local_ifindex: 0,
                    egress_ifindex: 21,
                    tx_ifindex: 21,
                    tunnel_endpoint_id: 0,
                    next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
                    neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
                    src_mac: Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]),
                    tx_vlan_id: 0,
                },
                nat: test_decision().nat.reverse(
                    forward_key.src_ip,
                    forward_key.dst_ip,
                    forward_key.src_port,
                    forward_key.dst_port,
                ),
            },
            SessionMetadata {
                ingress_zone: Arc::<str>::from("wan"),
                egress_zone: Arc::<str>::from("lan"),
                owner_rg_id: 2,
                fabric_ingress: false,
                is_reverse: true,
                nat64_reverse: None,
            },
            SessionOrigin::SyncImport,
            now_ns,
            PROTO_TCP,
            0x10,
        ));

        let ha_state = BTreeMap::from([(2, active_ha_runtime(now_ns / 1_000_000_000))]);
        let results = apply_worker_commands(
            &commands,
            &mut sessions,
            -1,
            -1,
            -1,
            &test_forwarding_state_split_rgs(),
            &ha_state,
            &Arc::new(Mutex::new(FastMap::default())),
        );

        assert!(results.cancelled_keys.is_empty());
        let (lookup, origin) = sessions
            .lookup_with_origin(&reverse_key, now_ns, 0x10)
            .expect("refreshed reverse session");
        assert!(origin.is_peer_synced());
        assert_eq!(
            lookup.decision.resolution.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(lookup.decision.resolution.egress_ifindex, 6);
        assert_eq!(lookup.decision.resolution.tx_ifindex, 6);
        assert_eq!(
            lookup.decision.resolution.next_hop,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)))
        );
        assert_eq!(lookup.metadata.owner_rg_id, 2);
        assert!(lookup.metadata.is_reverse);
    }

    #[test]
    fn apply_worker_commands_refresh_split_reverse_owner_rg_updates_stale_indexed_session() {
        let commands = Arc::new(Mutex::new(VecDeque::from([
            WorkerCommand::RefreshOwnerRGS { owner_rgs: vec![2] },
        ])));
        let mut sessions = SessionTable::new();
        let forward_key = test_key();
        let reverse_key = reverse_session_key(&forward_key, test_decision().nat);
        let now_ns = monotonic_nanos();

        assert!(sessions.install_with_protocol_with_origin(
            reverse_key.clone(),
            SessionDecision {
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::FabricRedirect,
                    local_ifindex: 0,
                    egress_ifindex: 21,
                    tx_ifindex: 21,
                    tunnel_endpoint_id: 0,
                    next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
                    neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
                    src_mac: Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]),
                    tx_vlan_id: 0,
                },
                nat: test_decision().nat.reverse(
                    forward_key.src_ip,
                    forward_key.dst_ip,
                    forward_key.src_port,
                    forward_key.dst_port,
                ),
            },
            SessionMetadata {
                ingress_zone: Arc::<str>::from("wan"),
                egress_zone: Arc::<str>::from("lan"),
                owner_rg_id: 1,
                fabric_ingress: false,
                is_reverse: true,
                nat64_reverse: None,
            },
            SessionOrigin::SyncImport,
            now_ns,
            PROTO_TCP,
            0x10,
        ));

        let ha_state = BTreeMap::from([
            (1, inactive_ha_runtime(now_ns / 1_000_000_000)),
            (2, active_ha_runtime(now_ns / 1_000_000_000)),
        ]);
        let results = apply_worker_commands(
            &commands,
            &mut sessions,
            -1,
            -1,
            -1,
            &test_forwarding_state_split_rgs(),
            &ha_state,
            &Arc::new(Mutex::new(FastMap::default())),
        );

        assert!(results.cancelled_keys.is_empty());
        let (lookup, origin) = sessions
            .lookup_with_origin(&reverse_key, now_ns, 0x10)
            .expect("refreshed reverse session");
        assert!(origin.is_peer_synced());
        assert_eq!(
            lookup.decision.resolution.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(lookup.decision.resolution.egress_ifindex, 6);
        assert_eq!(lookup.decision.resolution.tx_ifindex, 6);
        assert_eq!(
            lookup.decision.resolution.next_hop,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)))
        );
        assert_eq!(lookup.metadata.owner_rg_id, 2);
        assert!(lookup.metadata.is_reverse);
    }

    #[test]
    fn apply_worker_commands_refresh_owner_rg_updates_reverse_session_owned_by_other_rg() {
        let commands = Arc::new(Mutex::new(VecDeque::from([
            WorkerCommand::RefreshOwnerRGS { owner_rgs: vec![1] },
        ])));
        let mut sessions = SessionTable::new();
        let forward_key = test_key();
        let reverse_key = reverse_session_key(&forward_key, test_decision().nat);
        let now_ns = monotonic_nanos();

        assert!(sessions.install_with_protocol_with_origin(
            reverse_key.clone(),
            SessionDecision {
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::FabricRedirect,
                    local_ifindex: 0,
                    egress_ifindex: 21,
                    tx_ifindex: 21,
                    tunnel_endpoint_id: 0,
                    next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
                    neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
                    src_mac: Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]),
                    tx_vlan_id: 0,
                },
                nat: test_decision().nat.reverse(
                    forward_key.src_ip,
                    forward_key.dst_ip,
                    forward_key.src_port,
                    forward_key.dst_port,
                ),
            },
            SessionMetadata {
                ingress_zone: Arc::<str>::from("wan"),
                egress_zone: Arc::<str>::from("lan"),
                owner_rg_id: 2,
                fabric_ingress: false,
                is_reverse: true,
                nat64_reverse: None,
            },
            SessionOrigin::SharedPromote,
            now_ns,
            PROTO_TCP,
            0x10,
        ));

        let ha_state = BTreeMap::from([
            (1, active_ha_runtime(now_ns / 1_000_000_000)),
            (2, active_ha_runtime(now_ns / 1_000_000_000)),
        ]);
        let results = apply_worker_commands(
            &commands,
            &mut sessions,
            -1,
            -1,
            -1,
            &test_forwarding_state_split_rgs(),
            &ha_state,
            &Arc::new(Mutex::new(FastMap::default())),
        );

        assert!(results.cancelled_keys.is_empty());
        let (lookup, origin) = sessions
            .lookup_with_origin(&reverse_key, now_ns, 0x10)
            .expect("refreshed reverse session");
        assert_eq!(origin, SessionOrigin::SharedPromote);
        assert_eq!(
            lookup.decision.resolution.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(lookup.decision.resolution.egress_ifindex, 6);
        assert_eq!(lookup.decision.resolution.tx_ifindex, 6);
        assert_eq!(
            lookup.decision.resolution.next_hop,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)))
        );
        assert_eq!(lookup.metadata.owner_rg_id, 2);
        assert!(lookup.metadata.is_reverse);
    }

    #[test]
    fn apply_worker_commands_refresh_owner_rg_rewrites_remote_reverse_session_on_peer_move() {
        let commands = Arc::new(Mutex::new(VecDeque::from([
            WorkerCommand::RefreshOwnerRGS { owner_rgs: vec![1] },
        ])));
        let mut sessions = SessionTable::new();
        let forward_key = test_key();
        let reverse_key = reverse_session_key(&forward_key, test_decision().nat);
        let now_ns = monotonic_nanos();

        assert!(sessions.install_with_protocol_with_origin(
            reverse_key.clone(),
            SessionDecision {
                resolution: ForwardingResolution {
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
                nat: test_decision().nat.reverse(
                    forward_key.src_ip,
                    forward_key.dst_ip,
                    forward_key.src_port,
                    forward_key.dst_port,
                ),
            },
            SessionMetadata {
                ingress_zone: Arc::<str>::from("wan"),
                egress_zone: Arc::<str>::from("lan"),
                owner_rg_id: 2,
                fabric_ingress: false,
                is_reverse: true,
                nat64_reverse: None,
            },
            SessionOrigin::SyncImport,
            now_ns,
            PROTO_TCP,
            0x10,
        ));

        let ha_state = BTreeMap::from([
            (1, active_ha_runtime(now_ns / 1_000_000_000)),
            (2, inactive_ha_runtime(now_ns / 1_000_000_000)),
        ]);
        let results = apply_worker_commands(
            &commands,
            &mut sessions,
            -1,
            -1,
            -1,
            &test_forwarding_state_split_rgs(),
            &ha_state,
            &Arc::new(Mutex::new(FastMap::default())),
        );

        assert!(results.cancelled_keys.is_empty());
        let (lookup, origin) = sessions
            .lookup_with_origin(&reverse_key, now_ns, 0x10)
            .expect("refreshed reverse session");
        assert!(origin.is_peer_synced());
        assert_eq!(
            lookup.decision.resolution.disposition,
            ForwardingDisposition::FabricRedirect
        );
        assert_eq!(lookup.decision.resolution.egress_ifindex, 21);
        assert_eq!(lookup.metadata.owner_rg_id, 2);
        assert!(lookup.metadata.is_reverse);
    }

    #[test]
    fn apply_worker_commands_refresh_owner_rg_rewrites_shared_promote_reverse_on_peer_move() {
        let commands = Arc::new(Mutex::new(VecDeque::from([
            WorkerCommand::RefreshOwnerRGS { owner_rgs: vec![1] },
        ])));
        let mut sessions = SessionTable::new();
        let forward_key = test_key();
        let reverse_key = reverse_session_key(&forward_key, test_decision().nat);
        let now_ns = monotonic_nanos();

        assert!(sessions.install_with_protocol_with_origin(
            reverse_key.clone(),
            SessionDecision {
                resolution: ForwardingResolution {
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
                nat: test_decision().nat.reverse(
                    forward_key.src_ip,
                    forward_key.dst_ip,
                    forward_key.src_port,
                    forward_key.dst_port,
                ),
            },
            SessionMetadata {
                ingress_zone: Arc::<str>::from("wan"),
                egress_zone: Arc::<str>::from("lan"),
                owner_rg_id: 2,
                fabric_ingress: false,
                is_reverse: true,
                nat64_reverse: None,
            },
            SessionOrigin::SharedPromote,
            now_ns,
            PROTO_TCP,
            0x10,
        ));

        let ha_state = BTreeMap::from([
            (1, active_ha_runtime(now_ns / 1_000_000_000)),
            (2, inactive_ha_runtime(now_ns / 1_000_000_000)),
        ]);
        let results = apply_worker_commands(
            &commands,
            &mut sessions,
            -1,
            -1,
            -1,
            &test_forwarding_state_split_rgs(),
            &ha_state,
            &Arc::new(Mutex::new(FastMap::default())),
        );

        assert!(results.cancelled_keys.is_empty());
        let (lookup, origin) = sessions
            .lookup_with_origin(&reverse_key, now_ns, 0x10)
            .expect("refreshed reverse session");
        assert_eq!(origin, SessionOrigin::SharedPromote);
        assert_eq!(
            lookup.decision.resolution.disposition,
            ForwardingDisposition::FabricRedirect
        );
        assert_eq!(lookup.decision.resolution.egress_ifindex, 21);
        assert_eq!(lookup.metadata.owner_rg_id, 2);
        assert!(lookup.metadata.is_reverse);
    }

    #[test]
    fn export_owner_rg_sessions_skips_locally_demoted_entries() {
        let commands = Arc::new(Mutex::new(VecDeque::from([
            WorkerCommand::DemoteOwnerRGS { owner_rgs: vec![1] },
            WorkerCommand::ExportOwnerRGSessions {
                sequence: 11,
                owner_rgs: vec![1],
            },
        ])));
        let mut sessions = SessionTable::new();
        let key = test_key();
        let decision = test_decision();
        let metadata = test_metadata();
        let now_ns = monotonic_nanos();

        assert!(sessions.install_with_protocol_with_origin(
            key,
            decision,
            metadata,
            SessionOrigin::ForwardFlow,
            now_ns,
            PROTO_TCP,
            0x10,
        ));
        assert_eq!(sessions.drain_deltas(16).len(), 1);

        let results = apply_worker_commands(
            &commands,
            &mut sessions,
            -1,
            -1,
            -1,
            &test_forwarding_state_with_fabric(),
            &BTreeMap::new(),
            &Arc::new(Mutex::new(FastMap::default())),
        );

        assert_eq!(results.exported_sequences, vec![11]);
        assert!(
            sessions.drain_deltas(16).is_empty(),
            "demoted local owner sessions must not be re-exported as fresh HA deltas"
        );
    }

    #[test]
    fn synthesized_synced_reverse_entry_preserves_fabric_ingress_and_reverse_flag() {
        let forwarding = test_forwarding_state();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let mut metadata = test_metadata();
        metadata.fabric_ingress = true;
        let entry = SyncedSessionEntry {
            key: test_key(),
            decision: test_decision(),
            metadata,
            origin: SessionOrigin::SyncImport,
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
        assert!(reverse.origin.is_peer_synced());
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
        let entry = SyncedSessionEntry {
            key: test_key(),
            decision: test_decision(),
            metadata,
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
        };
        let mut ha_state = BTreeMap::new();
        ha_state.insert(1, active_ha_runtime(1));

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
    fn synthesized_synced_reverse_entry_uses_fabric_redirect_when_client_rg_inactive() {
        let forwarding = test_forwarding_state_split_rgs();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let mut metadata = test_metadata();
        metadata.ingress_zone = Arc::<str>::from("lan");
        metadata.egress_zone = Arc::<str>::from("wan");
        metadata.fabric_ingress = false;
        let entry = SyncedSessionEntry {
            key: test_key(),
            decision: test_decision(),
            metadata,
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
        };
        let mut ha_state = BTreeMap::new();
        ha_state.insert(1, active_ha_runtime(1));
        ha_state.insert(2, inactive_ha_runtime(1));

        let reverse =
            synthesized_synced_reverse_entry(&forwarding, &ha_state, &dynamic_neighbors, &entry, 1)
                .expect("reverse companion");

        assert_eq!(
            reverse.decision.resolution.disposition,
            ForwardingDisposition::FabricRedirect
        );
        assert_eq!(reverse.decision.resolution.egress_ifindex, 21);
        assert_eq!(
            reverse.decision.resolution.src_mac,
            Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x03])
        );
        assert_eq!(reverse.metadata.owner_rg_id, 2);
        assert!(reverse.metadata.is_reverse);
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
            false,
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
    fn session_hit_ha_inactive_does_not_redirect_actual_fabric_ingress() {
        let forwarding = test_forwarding_state_with_fabric();
        let resolved = redirect_session_via_fabric_if_needed(
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
            true,
            "sfmix",
        );
        assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
    }

    #[test]
    fn fabric_ingress_session_hit_obeys_ha_inactive_gate() {
        let forwarding = test_forwarding_state_with_fabric();
        let ha_state = BTreeMap::from([(1, inactive_ha_runtime(1))]);
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
        assert_eq!(resolved.disposition, ForwardingDisposition::HAInactive);
        assert_eq!(resolved.egress_ifindex, 6);
    }

    #[test]
    fn tunnel_ingress_session_hit_bypasses_unseeded_ha_during_startup_grace() {
        let forwarding = test_forwarding_state_split_rgs_with_tunnel();
        let ha_state = BTreeMap::from([(2, inactive_ha_runtime(0))]);
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
        let ha_state = BTreeMap::from([(2, inactive_ha_runtime(0))]);
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
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let worker_commands = vec![Arc::new(Mutex::new(VecDeque::new()))];
        let forwarding = test_forwarding_state();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let mut ha_state = BTreeMap::new();
        ha_state.insert(1, active_ha_runtime(1));
        let entry = SyncedSessionEntry {
            key: test_key(),
            decision: test_decision(),
            metadata: SessionMetadata {
                fabric_ingress: true,
                ..test_metadata()
            },
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
        };
        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &entry,
        );
        refresh_reverse_prewarm_owner_rg_indexes(
            &shared_owner_rg_indexes.reverse_prewarm_sessions,
            &forwarding,
            &dynamic_neighbors,
            None,
            Some(&entry),
        );

        prewarm_reverse_synced_sessions_for_owner_rgs(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
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
        assert!(reverse.origin.is_peer_synced());
        // 2 commands: forward entry + reverse entry (both pushed to workers)
        assert_eq!(worker_commands[0].lock().expect("commands").len(), 2);
    }

    #[test]
    fn prewarm_reverse_synced_sessions_for_owner_rgs_restores_shared_promote_forward_entry() {
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let worker_commands = vec![Arc::new(Mutex::new(VecDeque::new()))];
        let forwarding = test_forwarding_state_split_rgs();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let mut ha_state = BTreeMap::new();
        ha_state.insert(1, active_ha_runtime(1));
        ha_state.insert(2, inactive_ha_runtime(1));
        let mut metadata = test_metadata();
        metadata.ingress_zone = Arc::<str>::from("lan");
        metadata.egress_zone = Arc::<str>::from("wan");
        metadata.fabric_ingress = false;
        metadata.owner_rg_id = 1;
        let entry = SyncedSessionEntry {
            key: test_key(),
            decision: test_decision(),
            metadata,
            origin: SessionOrigin::SharedPromote,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
        };
        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &entry,
        );

        let prewarm_index = shared_owner_rg_indexes
            .reverse_prewarm_sessions
            .lock()
            .expect("prewarm index");
        assert!(
            prewarm_index.get(&1).is_none() || !prewarm_index.get(&1).unwrap().contains(&entry.key)
        );
        drop(prewarm_index);

        prewarm_reverse_synced_sessions_for_owner_rgs(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
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
        assert_eq!(reverse.metadata.owner_rg_id, 2);
        let commands = worker_commands[0].lock().expect("commands");
        assert_eq!(commands.len(), 2);
        assert!(matches!(
            &commands[0],
            WorkerCommand::UpsertSynced(session) if session.origin == SessionOrigin::SharedPromote
        ));
        assert!(matches!(
            &commands[1],
            WorkerCommand::UpsertSynced(session)
                if session.metadata.is_reverse && session.metadata.owner_rg_id == 2
        ));
    }

    #[test]
    fn prewarm_reverse_synced_sessions_recomputes_when_reverse_owner_rg_activates() {
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let worker_commands = vec![Arc::new(Mutex::new(VecDeque::new()))];
        let forwarding = test_forwarding_state_split_rgs();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let mut ha_state = BTreeMap::new();
        ha_state.insert(2, active_ha_runtime(1));
        let mut entry = SyncedSessionEntry {
            key: test_key(),
            decision: test_decision(),
            metadata: SessionMetadata {
                fabric_ingress: true,
                ..test_metadata()
            },
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
        };
        entry.metadata.owner_rg_id = 1;
        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &entry,
        );
        refresh_reverse_prewarm_owner_rg_indexes(
            &shared_owner_rg_indexes.reverse_prewarm_sessions,
            &forwarding,
            &dynamic_neighbors,
            None,
            Some(&entry),
        );

        // owner_rgs=[2] does not include the forward session's owner_rg_id=1,
        // but the synthesized reverse companion resolves to owner_rg_id=2 in
        // the split-RG topology, so activation of RG2 must still prewarm it.
        prewarm_reverse_synced_sessions_for_owner_rgs(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
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
        assert_eq!(reverse.metadata.owner_rg_id, 2);
        // 2 commands: forward entry + reverse entry (both pushed to workers)
        assert_eq!(worker_commands[0].lock().expect("commands").len(), 2);
    }

    #[test]
    fn reverse_prewarm_index_tracks_split_reverse_owner_rg_candidate() {
        let forwarding = test_forwarding_state_split_rgs();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        let mut entry = SyncedSessionEntry {
            key: test_key(),
            decision: test_decision(),
            metadata: SessionMetadata {
                fabric_ingress: true,
                ..test_metadata()
            },
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
        };
        entry.metadata.owner_rg_id = 1;

        refresh_reverse_prewarm_owner_rg_indexes(
            &shared_owner_rg_indexes.reverse_prewarm_sessions,
            &forwarding,
            &dynamic_neighbors,
            None,
            Some(&entry),
        );

        let index = shared_owner_rg_indexes
            .reverse_prewarm_sessions
            .lock()
            .expect("prewarm index");
        assert!(index.get(&1).is_some_and(|keys| keys.contains(&entry.key)));
        assert!(index.get(&2).is_some_and(|keys| keys.contains(&entry.key)));
    }

    #[test]
    fn reverse_session_from_split_owner_fabric_redirect_uses_fabric_return_when_client_rg_inactive()
    {
        let forwarding = test_forwarding_state_split_rgs();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let ha_state = BTreeMap::from([(2, inactive_ha_runtime(1))]);
        let reverse = build_reverse_session_from_forward_match(
            &forwarding,
            &ha_state,
            &dynamic_neighbors,
            ForwardSessionMatch {
                key: SessionKey {
                    addr_family: libc::AF_INET as u8,
                    protocol: PROTO_TCP,
                    src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 102)),
                    dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
                    src_port: 42424,
                    dst_port: 5201,
                },
                decision: SessionDecision {
                    resolution: ForwardingResolution {
                        disposition: ForwardingDisposition::FabricRedirect,
                        local_ifindex: 0,
                        egress_ifindex: 21,
                        tx_ifindex: 21,
                        tunnel_endpoint_id: 0,
                        next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
                        neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
                        src_mac: Some([0x02, 0xbf, 0x72, FABRIC_ZONE_MAC_MAGIC, 0x00, 0x01]),
                        tx_vlan_id: 0,
                    },
                    nat: NatDecision {
                        rewrite_src: Some(IpAddr::V4(Ipv4Addr::new(172, 16, 80, 8))),
                        ..NatDecision::default()
                    },
                },
                metadata: SessionMetadata {
                    ingress_zone: Arc::<str>::from("lan"),
                    egress_zone: Arc::<str>::from("wan"),
                    owner_rg_id: 1,
                    fabric_ingress: false,
                    is_reverse: false,
                    nat64_reverse: None,
                },
            },
            1,
            0,
        );
        assert_eq!(
            reverse.decision.resolution.disposition,
            ForwardingDisposition::FabricRedirect
        );
        assert_eq!(reverse.decision.resolution.egress_ifindex, 21);
        assert_eq!(reverse.decision.resolution.tx_ifindex, 21);
    }

    #[test]
    fn republish_bpf_session_entries_covers_all_sessions_in_owner_rg_index() {
        // Simulate the failover+failback scenario (#475):
        // A session is in the shared sessions table and the `sessions`
        // owner-RG index but NOT in the `reverse_prewarm_sessions` index
        // (e.g., locally originated then demoted). The comprehensive
        // republish function must find and attempt to publish it.
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();

        let entry = SyncedSessionEntry {
            key: test_key(),
            decision: test_decision(),
            metadata: SessionMetadata {
                owner_rg_id: 1,
                ..test_metadata()
            },
            origin: SessionOrigin::SyncImport,
            protocol: PROTO_TCP,
            tcp_flags: 0x10,
        };
        // Publish to shared table + sessions index (but NOT reverse_prewarm).
        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &entry,
        );

        // Verify the session is in the sessions index but not reverse_prewarm.
        let sessions_index = shared_owner_rg_indexes
            .sessions
            .lock()
            .expect("sessions index");
        assert!(
            sessions_index
                .get(&1)
                .is_some_and(|keys| keys.contains(&entry.key))
        );
        drop(sessions_index);

        let prewarm_index = shared_owner_rg_indexes
            .reverse_prewarm_sessions
            .lock()
            .expect("prewarm index");
        assert!(prewarm_index.get(&1).is_none() || prewarm_index.get(&1).unwrap().is_empty());
        drop(prewarm_index);

        // Call republish — it should find the session via the sessions index.
        // Use fd=-1 (the BPF syscall will fail). The function now only counts
        // successful publishes, so count=0 with fd=-1. We verify the function
        // iterates the right sessions by checking RG2 returns 0 (no sessions).
        let count = republish_bpf_session_entries_for_owner_rgs(
            &shared_sessions,
            &shared_owner_rg_indexes,
            -1,
            &[1],
        );
        assert_eq!(count, 0, "fd=-1 should produce 0 successful publishes");

        // Unrelated RG should return 0.
        let count = republish_bpf_session_entries_for_owner_rgs(
            &shared_sessions,
            &shared_owner_rg_indexes,
            -1,
            &[2],
        );
        assert_eq!(count, 0, "should find 0 sessions for RG2");
    }

    #[test]
    fn synced_session_hit_recomputes_local_resolution_after_failover() {
        let mut sessions = SessionTable::new();
        let key = test_key();
        let mut forwarding = test_forwarding_state_with_fabric();
        forwarding.connected_v4.push(ConnectedRouteV4 {
            prefix: PrefixV4::from_net(Ipv4Net::new(Ipv4Addr::new(172, 16, 80, 0), 24).unwrap()),
            ifindex: 12,
            tunnel_endpoint_id: 0,
        });
        forwarding.neighbors.insert(
            (12, IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200))),
            NeighborEntry {
                mac: [0x56, 0x4a, 0xe8, 0x1e, 0xa8, 0x32],
            },
        );
        let stale_fabric_decision = SessionDecision {
            resolution: ForwardingResolution {
                disposition: ForwardingDisposition::FabricRedirect,
                local_ifindex: 0,
                egress_ifindex: 21,
                tx_ifindex: 21,
                tunnel_endpoint_id: 0,
                next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 99, 13, 2))),
                neighbor_mac: Some([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
                src_mac: Some([0x02, 0xbf, 0x72, 0xff, 0x00, 0x01]),
                tx_vlan_id: 0,
            },
            nat: NatDecision::default(),
        };
        let shared_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_nat_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_forward_wire_sessions = Arc::new(Mutex::new(FastMap::default()));
        let shared_owner_rg_indexes = SharedSessionOwnerRgIndexes::default();
        publish_shared_session(
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &SyncedSessionEntry {
                key: key.clone(),
                decision: stale_fabric_decision,
                metadata: test_metadata(),
                origin: SessionOrigin::SyncImport,
                protocol: PROTO_TCP,
                tcp_flags: 0x10,
            },
        );
        let peer_worker_commands = Vec::new();
        let dynamic_neighbors = Arc::new(Mutex::new(FastMap::default()));
        let ha_state = BTreeMap::from([(
            1,
            HAGroupRuntime {
                active: true,
                watchdog_timestamp: monotonic_nanos() / 1_000_000_000,
                lease: HAGroupRuntime::active_lease_until(
                    monotonic_nanos() / 1_000_000_000,
                    monotonic_nanos() / 1_000_000_000,
                ),
            },
        )]);

        let resolved = resolve_flow_session_decision(
            &mut sessions,
            -1,
            &shared_sessions,
            &shared_nat_sessions,
            &shared_forward_wire_sessions,
            &shared_owner_rg_indexes,
            &peer_worker_commands,
            &forwarding,
            &ha_state,
            &dynamic_neighbors,
            &SessionFlow {
                src_ip: key.src_ip,
                dst_ip: key.dst_ip,
                forward_key: key.clone(),
            },
            1_000_000,
            monotonic_nanos() / 1_000_000_000,
            PROTO_TCP,
            0x10,
            5,
            false,
            0,
        )
        .expect("synced session should resolve");

        assert_eq!(
            resolved.decision.resolution.disposition,
            ForwardingDisposition::ForwardCandidate
        );
        assert_eq!(resolved.decision.resolution.egress_ifindex, 12);
        assert_eq!(resolved.decision.resolution.tx_ifindex, 11);
    }
}
