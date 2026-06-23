use super::*;

const LOCAL_TUNNEL_SESSION_PRUNE_INTERVAL_NS: u64 = 5_000_000_000;
const LOCAL_TUNNEL_SESSION_STALE_NS: u64 = 30_000_000_000;
const LOCAL_TUNNEL_SESSION_PRUNE_THRESHOLD: usize = 4096;

fn local_tunnel_io_error_is_fatal(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(code)
            if code == libc::EINVAL
                || code == libc::EBADF
                || code == libc::EBADFD
                || code == libc::ENODEV
                || code == libc::ENXIO
    )
}

/// #1881: fatal-errno predicate for TUN delivery WRITES. Differs from
/// the read predicate in exactly one errno: `EINVAL` on a TUN write
/// means the kernel rejected THAT PACKET (malformed/mis-sliced inner
/// — e.g. the off-by-VLAN local-delivery extraction observed live on
/// the loss cluster), a per-packet condition. Treating it as fatal
/// let ONE bad delivery kill the local-origin thread — permanently on
/// pre-#1881 master (no respawn), and as a 15s tombstone/respawn churn
/// loop with the #1881 liveness (every peer keepalive reply re-killed
/// the fresh thread). On READS, `EINVAL` remains fatal (fd/iface-level
/// condition). `EBADF`/`EBADFD`/`ENODEV`/`ENXIO` stay fatal in both
/// directions — the fd is genuinely dead (anchor deleted/recreated).
fn local_tunnel_write_error_is_fatal(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(code)
            if code == libc::EBADF
                || code == libc::EBADFD
                || code == libc::ENODEV
                || code == libc::ENXIO
    )
}

pub(super) enum LocalTunnelDrainOutcome {
    /// `stop` observed — the loop must return so the coordinator's
    /// join is bounded even under a busy delivery producer (#1881,
    /// Codex plan r1 MAJOR 2: the pre-#1881 drain ran to
    /// `Empty`/`Disconnected` only, and the queue is deep enough for
    /// a producer to keep it non-empty indefinitely).
    Stopped,
    /// Fatal TUN write errno — the loop must exit (finished sweep
    /// tombstones the entry; liveness respawns it with a fresh fd).
    FatalIo,
    /// Queue drained (or one non-fatal write error) — proceed to the
    /// TUN read.
    Drained,
}

/// #1881: one bounded delivery-drain chunk, extracted from
/// `local_tunnel_source_loop` so the stop-latency contract is unit
/// testable (plan §9 test 4).
pub(super) fn drain_local_tunnel_deliveries(
    tun: &mut impl Write,
    delivery_rx: &Receiver<Vec<u8>>,
    stop: &AtomicBool,
    tunnel_name: &str,
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
) -> LocalTunnelDrainOutcome {
    loop {
        if stop.load(Ordering::Relaxed) {
            return LocalTunnelDrainOutcome::Stopped;
        }
        match delivery_rx.try_recv() {
            Ok(packet) => {
                if let Err(err) = tun.write_all(&packet) {
                    record_local_tunnel_exception(
                        recent_exceptions,
                        tunnel_name,
                        format!("write_local_tunnel_delivery:{err}"),
                    );
                    if local_tunnel_write_error_is_fatal(&err) {
                        return LocalTunnelDrainOutcome::FatalIo;
                    }
                    return LocalTunnelDrainOutcome::Drained;
                }
            }
            Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => {
                return LocalTunnelDrainOutcome::Drained;
            }
        }
    }
}

/// #1881 D.1b: whether the loaded forwarding state still describes
/// the tunnel this thread is attached to. The TUN fd is bound to the
/// netdev captured at spawn — if the endpoint is gone, no longer a
/// GRE mode, or re-attached to a different ifindex/name, this thread
/// must PARK (drop without building) until the coordinator prune
/// joins it. Recomputed ONLY when the forwarding Arc rotates, so the
/// steady-state per-packet cost is zero. This is the correctness
/// boundary for the store-to-join window in
/// `refresh_runtime_snapshot_inner`: the #1873 owner check compares
/// the endpoint row against a resolution derived from the SAME
/// loaded state, so it cannot detect a thread reading the wrong TUN.
pub(super) fn endpoint_attachment_valid(
    forwarding: &ForwardingState,
    tunnel_endpoint_id: u16,
    spawned_logical_ifindex: i32,
    spawned_tunnel_name: &str,
) -> bool {
    let Some(endpoint) = forwarding.tunnel_endpoints.get(&tunnel_endpoint_id) else {
        return false;
    };
    if endpoint.mode != "gre" && endpoint.mode != "ip6gre" {
        return false;
    }
    endpoint.logical_ifindex == spawned_logical_ifindex
        && forwarding
            .ifindex_to_name
            .get(&endpoint.logical_ifindex)
            .is_some_and(|name| name == spawned_tunnel_name)
}

pub(super) fn local_tunnel_source_loop(
    tunnel_name: String,
    tunnel_endpoint_id: u16,
    spawned_logical_ifindex: i32,
    shared_forwarding: Arc<ArcSwap<ForwardingState>>,
    ha_state: Arc<ArcSwap<BTreeMap<i32, HAGroupRuntime>>>,
    dynamic_neighbors: Arc<ShardedNeighborMap>,
    live: BTreeMap<u32, Arc<BindingLiveState>>,
    identities: BTreeMap<u32, BindingIdentity>,
    shared_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: SharedSessionOwnerRgIndexes,
    worker_commands: Vec<Arc<Mutex<VecDeque<WorkerCommand>>>>,
    delivery_rx: Receiver<Vec<u8>>,
    recent_exceptions: Arc<Mutex<VecDeque<ExceptionStatus>>>,
    stop: Arc<AtomicBool>,
) {
    let mut tun = match open_tun(&tunnel_name) {
        Ok((file, _actual_name)) => file,
        Err(err) => {
            record_local_tunnel_exception(&recent_exceptions, &tunnel_name, err);
            return;
        }
    };
    if let Err(err) = set_fd_nonblocking(tun.as_raw_fd()) {
        record_local_tunnel_exception(&recent_exceptions, &tunnel_name, err);
        return;
    }

    let mut packet = vec![0u8; 65_536];
    let mut next_slot = 0usize;
    let mut local_sessions = FastMap::<SessionKey, u64>::default();
    let mut local_sessions_last_prune_ns = 0u64;
    // #1881 D.1: track the worker-visible forwarding ArcSwap instead
    // of a spawn-time clone. ONE load point per outer iteration (the
    // #1188 ptr_eq short-circuit); the same Arc is used for the WHOLE
    // packet build below, so resolution, session synthesis, CoS, and
    // encap are coherent by construction. Cost honesty: this loop is
    // syscall-paced (one read(2) per iteration, 1ms sleep when idle,
    // single-digit pps workload) — an iteration IS the batch (≤1
    // packet), so the per-BATCH ArcSwap rule holds and the AF_XDP
    // worker hot path is untouched.
    let mut forwarding: Arc<ForwardingState> = shared_forwarding.load_full();
    let mut endpoint_attached = endpoint_attachment_valid(
        &forwarding,
        tunnel_endpoint_id,
        spawned_logical_ifindex,
        &tunnel_name,
    );
    while !stop.load(Ordering::Relaxed) {
        if let Some(new_forwarding) =
            super::worker::load_arc_if_changed(&forwarding, &shared_forwarding)
        {
            forwarding = new_forwarding;
            endpoint_attached = endpoint_attachment_valid(
                &forwarding,
                tunnel_endpoint_id,
                spawned_logical_ifindex,
                &tunnel_name,
            );
        }
        // #1881 (AGY plan r1): ONE HA-state load per iteration, passed
        // down so resolution enforcement and reverse-entry synthesis
        // see the same map. Cross-source (forwarding↔HA) atomicity is
        // not claimed — they are published independently by design,
        // matching the worker path.
        let ha_runtime = ha_state.load();
        match drain_local_tunnel_deliveries(
            &mut tun,
            &delivery_rx,
            &stop,
            &tunnel_name,
            &recent_exceptions,
        ) {
            LocalTunnelDrainOutcome::Stopped | LocalTunnelDrainOutcome::FatalIo => return,
            LocalTunnelDrainOutcome::Drained => {}
        }
        match tun.read(&mut packet) {
            Ok(0) => thread::sleep(Duration::from_millis(1)),
            Ok(len) => {
                // #1881 D.1b: parked — the loaded state no longer
                // describes this thread's TUN attachment (endpoint
                // removed, mode flipped, or reattached). Drop without
                // building; the coordinator prune will join us. Keep
                // reading so the TUN never backs up.
                if !endpoint_attached {
                    debug_log!(
                        "LOCAL_TUNNEL[{}]: drop endpoint={} reason=local_tunnel_unattached",
                        tunnel_name,
                        tunnel_endpoint_id
                    );
                    continue;
                }
                let packet = &packet[..len];
                match build_local_origin_tunnel_tx_request(
                    packet,
                    tunnel_endpoint_id,
                    &forwarding,
                    ha_runtime.as_ref(),
                    &dynamic_neighbors,
                ) {
                    Ok(plan) => {
                        maybe_enqueue_local_tunnel_session(
                            &shared_sessions,
                            &shared_nat_sessions,
                            &shared_forward_wire_sessions,
                            &shared_owner_rg_indexes,
                            &worker_commands,
                            &mut local_sessions,
                            &mut local_sessions_last_prune_ns,
                            &plan,
                        );
                        if let Some(target_live) = select_live_binding_for_ifindex(
                            &identities,
                            &live,
                            plan.tx_ifindex,
                            next_slot,
                        ) {
                            next_slot = next_slot.wrapping_add(1);
                            if let Err(err) = target_live.enqueue_tx(plan.tx_request) {
                                record_local_tunnel_exception(
                                    &recent_exceptions,
                                    &tunnel_name,
                                    format!("enqueue_local_tunnel_tx:{err}"),
                                );
                            }
                        } else {
                            record_local_tunnel_exception(
                                &recent_exceptions,
                                &tunnel_name,
                                format!("no_live_binding_for_tx_ifindex:{}", plan.tx_ifindex),
                            );
                        }
                    }
                    Err(err) => {
                        #[cfg(not(feature = "debug-log"))]
                        let _ = &err;
                        debug_log!(
                            "LOCAL_TUNNEL[{}]: drop endpoint={} reason={}",
                            tunnel_name,
                            tunnel_endpoint_id,
                            err
                        );
                    }
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(err) => {
                record_local_tunnel_exception(
                    &recent_exceptions,
                    &tunnel_name,
                    format!("read_local_tunnel:{err}"),
                );
                if local_tunnel_io_error_is_fatal(&err) {
                    return;
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

pub(super) fn build_local_origin_tunnel_tx_request(
    packet: &[u8],
    tunnel_endpoint_id: u16,
    forwarding: &ForwardingState,
    ha_runtime: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
) -> Result<LocalTunnelTxPlan, String> {
    let mut meta = local_origin_packet_meta(packet)
        .ok_or_else(|| "unsupported_local_origin_packet".to_string())?;
    let inner_frame = wrap_raw_ip_packet_for_tunnel(packet, meta.addr_family);
    meta.l3_offset = 14;
    meta.l4_offset = meta.l4_offset.saturating_add(14);
    meta.payload_offset = meta.payload_offset.saturating_add(14);
    // #1881 (AGY plan r1): the caller loads HA state ONCE per loop
    // iteration and passes the map down — resolution enforcement and
    // the reverse-entry synthesis below must see the same HA map.
    let resolution = enforce_ha_resolution_snapshot(
        forwarding,
        ha_runtime,
        monotonic_nanos() / 1_000_000_000,
        resolve_tunnel_forwarding_resolution(
            forwarding,
            Some(dynamic_neighbors),
            tunnel_endpoint_id,
            0,
        ),
    );
    if resolution.disposition != ForwardingDisposition::ForwardCandidate {
        return Err(format!(
            "local_tunnel_resolution:{}",
            resolution.status(None, forwarding).disposition
        ));
    }
    let decision = SessionDecision {
        resolution,
        nat: NatDecision::default(),
    };
    let flow = parse_session_flow_from_bytes(&inner_frame, meta)
        .ok_or_else(|| "parse_local_origin_session_flow_failed".to_string())?;
    // #921: zone_id is now a u16 field on EgressInterface — direct
    // load, no name round-trip.
    let zone_id = forwarding
        .egress
        .get(&decision.resolution.egress_ifindex)
        .map(|iface| iface.zone_id)
        .unwrap_or(0);
    let bytes = encapsulate_native_gre_frame(&inner_frame, meta, &decision, forwarding)
        .ok_or_else(|| "encapsulate_native_gre_frame_failed".to_string())?;
    let session_entry = SyncedSessionEntry {
        key: flow.forward_key,
        decision,
        metadata: SessionMetadata {
            ingress_zone: zone_id,
            egress_zone: zone_id,
            owner_rg_id: owner_rg_for_resolution(forwarding, decision.resolution),
            fabric_ingress: false,
            is_reverse: false,
            nat64_reverse: None,
        },
        origin: SessionOrigin::SyncImport,
        protocol: meta.protocol,
        tcp_flags: if meta.protocol == PROTO_TCP {
            extract_tcp_flags_and_window(&inner_frame)
                .map(|(flags, _)| flags)
                .unwrap_or_default()
        } else {
            0
        },
        // Locally decapsulated tunnel session: no peer install generation (#2170).
        generation: 0,
    };
    let reverse_session_entry = synthesized_synced_reverse_entry(
        forwarding,
        ha_runtime,
        dynamic_neighbors,
        &session_entry,
        monotonic_nanos() / 1_000_000_000,
    );
    let now_ns = monotonic_nanos();
    // #2362 fold B: local tunnel-origin path — the inner-frame L3/L4 offsets in
    // `meta` describe the pre-encap packet, so use the meta-only extra
    // (tcp_flags authoritative; is-fragment / icmp-type under-match on this rare
    // local path rather than risk mis-parsing inner offsets).
    let cos_extra = crate::afxdp::frame::term_match_extra_from_meta(meta.into());
    let cos = resolve_cos_tx_selection_at(
        forwarding,
        decision.resolution.egress_ifindex,
        meta,
        Some(&session_entry.key),
        cos_extra,
        now_ns,
    );
    if cos.drop {
        return Err("local_tunnel_packet_dropped_by_three_color_policer".to_string());
    }
    Ok(LocalTunnelTxPlan {
        tx_ifindex: decision.resolution.tx_ifindex,
        tx_request: TxRequest {
            bytes,
            expected_ports: None,
            expected_addr_family: meta.addr_family,
            expected_protocol: meta.protocol,
            flow_key: Some(session_entry.key.clone()),
            egress_ifindex: decision.resolution.egress_ifindex,
            cos_queue_id: cos.queue_id,
            dscp_rewrite: cos.dscp_rewrite,
            mirror_clone: false,
            enqueue_ns: 0,
        },
        session_entry,
        reverse_session_entry,
    })
}

pub(super) fn local_origin_packet_meta(packet: &[u8]) -> Option<UserspaceDpMeta> {
    let version = packet.first()? >> 4;
    let addr_family = match version {
        4 => libc::AF_INET as u8,
        6 => libc::AF_INET6 as u8,
        _ => return None,
    };
    let (l4_offset, protocol) = packet_rel_l4_offset_and_protocol(packet, addr_family)?;
    Some(UserspaceDpMeta {
        magic: USERSPACE_META_MAGIC,
        version: USERSPACE_META_VERSION,
        length: std::mem::size_of::<UserspaceDpMeta>() as u16,
        l4_offset: l4_offset.min(u16::MAX as usize) as u16,
        payload_offset: l4_offset.min(u16::MAX as usize) as u16,
        pkt_len: packet.len().min(u16::MAX as usize) as u16,
        addr_family,
        protocol,
        ..UserspaceDpMeta::default()
    })
}

pub(super) fn wrap_raw_ip_packet_for_tunnel(packet: &[u8], addr_family: u8) -> Vec<u8> {
    let mut frame = vec![0u8; 14 + packet.len()];
    frame[12..14].copy_from_slice(if addr_family as i32 == libc::AF_INET {
        &[0x08, 0x00]
    } else {
        &[0x86, 0xdd]
    });
    frame[14..].copy_from_slice(packet);
    frame
}

pub(super) fn maybe_enqueue_local_tunnel_session(
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    local_sessions: &mut FastMap<SessionKey, u64>,
    local_sessions_last_prune_ns: &mut u64,
    plan: &LocalTunnelTxPlan,
) {
    let now_ns = monotonic_nanos();
    prune_local_tunnel_sessions(local_sessions, local_sessions_last_prune_ns, now_ns);
    let entry = &plan.session_entry;
    let refresh_after_ns = if matches!(entry.protocol, PROTO_TCP) {
        5_000_000_000
    } else {
        1_000_000_000
    };
    if matches!(
        local_sessions.get(&entry.key),
        Some(last) if now_ns.saturating_sub(*last) < refresh_after_ns
    ) {
        return;
    }
    local_sessions.insert(entry.key.clone(), now_ns);
    publish_shared_session(
        shared_sessions,
        shared_nat_sessions,
        shared_forward_wire_sessions,
        shared_owner_rg_indexes,
        entry,
    );
    if let Some(reverse) = &plan.reverse_session_entry {
        publish_shared_session(
            shared_sessions,
            shared_nat_sessions,
            shared_forward_wire_sessions,
            shared_owner_rg_indexes,
            reverse,
        );
    }
    for pending in worker_commands {
        // #1807: recover-and-push — `if let Ok` silently DROPPED the
        // local-tunnel UpsertLocal pair for a poisoned worker queue. A
        // panic between the forward and reverse pushes leaves the
        // committed prefix (forward only); commands are self-contained.
        {
            let mut pending = worker_queue::lock_recover(pending);
            pending.push_back(WorkerCommand::UpsertLocal(entry.clone()));
            if let Some(reverse) = &plan.reverse_session_entry {
                pending.push_back(WorkerCommand::UpsertLocal(reverse.clone()));
            }
        }
    }
    wait_for_local_tunnel_session_install(worker_commands, now_ns + 1_000_000);
}

fn prune_local_tunnel_sessions(
    local_sessions: &mut FastMap<SessionKey, u64>,
    last_prune_ns: &mut u64,
    now_ns: u64,
) {
    if local_sessions.len() < LOCAL_TUNNEL_SESSION_PRUNE_THRESHOLD
        || now_ns.saturating_sub(*last_prune_ns) < LOCAL_TUNNEL_SESSION_PRUNE_INTERVAL_NS
    {
        return;
    }
    let cutoff_ns = now_ns.saturating_sub(LOCAL_TUNNEL_SESSION_STALE_NS);
    local_sessions.retain(|_, seen_ns| *seen_ns >= cutoff_ns);
    *last_prune_ns = now_ns;
}

pub(super) fn wait_for_local_tunnel_session_install(
    worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    deadline_ns: u64,
) {
    while monotonic_nanos() < deadline_ns {
        // #1807: a recovered (previously poisoned) guard is read as a
        // normal queue — poison used to read as "not drained" and spun
        // this wait until its deadline.
        let all_drained = worker_commands
            .iter()
            .all(|pending| worker_queue::lock_recover(pending).is_empty());
        if all_drained {
            break;
        }
        std::hint::spin_loop();
        thread::sleep(Duration::from_micros(50));
    }
}

pub(super) fn select_live_binding_for_ifindex(
    identities: &BTreeMap<u32, BindingIdentity>,
    live: &BTreeMap<u32, Arc<BindingLiveState>>,
    tx_ifindex: i32,
    next_slot: usize,
) -> Option<Arc<BindingLiveState>> {
    let mut candidate_count = 0usize;
    for identity in identities.values() {
        if identity.ifindex != tx_ifindex {
            continue;
        }
        if let Some(live_state) = live.get(&identity.slot) {
            if live_state.bound.load(Ordering::Relaxed) {
                candidate_count += 1;
            }
        }
    }
    if candidate_count == 0 {
        return None;
    }
    let target_index = next_slot % candidate_count;
    let mut current_index = 0usize;
    for identity in identities.values() {
        if identity.ifindex != tx_ifindex {
            continue;
        }
        if let Some(live_state) = live.get(&identity.slot) {
            if live_state.bound.load(Ordering::Relaxed) {
                if current_index == target_index {
                    return Some(live_state.clone());
                }
                current_index += 1;
            }
        }
    }
    None
}

pub(super) fn set_fd_nonblocking(fd: c_int) -> Result<(), String> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(format!(
            "fcntl(F_GETFL) failed: {}",
            io::Error::last_os_error()
        ));
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(format!(
            "fcntl(F_SETFL,O_NONBLOCK) failed: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "tunnel_tests.rs"]
mod tests;

pub(super) fn record_local_tunnel_exception(
    recent_exceptions: &Arc<Mutex<VecDeque<ExceptionStatus>>>,
    tunnel_name: &str,
    reason: String,
) {
    if let Ok(mut recent) = recent_exceptions.lock() {
        push_recent_exception(
            &mut recent,
            ExceptionStatus {
                timestamp: Utc::now(),
                interface: tunnel_name.to_string(),
                reason,
                ..ExceptionStatus::default()
            },
        );
    }
}
