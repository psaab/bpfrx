// Session-delta processing extracted from afxdp.rs (Issue 67.1).
// `flush_session_deltas` is the workhorse: it drains the per-binding
// SessionDelta queues, applies them to the SessionTable, and emits
// the corresponding session-life events to the event-stream channel.
// `purge_queued_flows_for_closed_deltas` post-processes per-binding
// pending-forward queues to drop frames whose flow is now closed,
// and `session_delta_event` is a tiny string-mapping helper.
//
// Pure relocation. `use super::*;` brings every type, helper, and
// sibling-submodule item from afxdp.rs into scope.

use super::*;

pub(super) fn purge_queued_flows_for_closed_deltas(
    bindings: &mut [BindingWorker],
    binding_lookup: &WorkerBindingLookup,
    shared_recycles: &mut Vec<(u32, u64)>,
    deltas: &[SessionDelta],
) {
    for delta in deltas {
        if delta.kind != SessionDeltaKind::Close {
            continue;
        }
        let reverse_key = reverse_session_key(&delta.key, delta.decision.nat);
        for binding in bindings.iter_mut() {
            cancel_queued_flow_on_binding(
                binding,
                &delta.key,
                &reverse_key,
                Some(shared_recycles),
            );
        }
        apply_shared_recycles_to_bindings(bindings, binding_lookup, shared_recycles);
    }
}

// #2669: `live` is `Option` because a drain cycle can coincide with an
// empty `bindings` slice (XSK sockets admin-down / unconfigured during a
// reload or transaction while the session table is still aging entries
// out). The drained deltas MUST still reach every binding-independent
// consumer — the shared session/conntrack tables, the peer-worker command
// queues, the HA delete replication, the recent-deltas RPC buffer, and the
// event stream — so they are flushed unconditionally below. Only the
// per-binding RPC fallback push (`live.push_session_delta`) is gated on a
// binding existing: with no binding there is no interface-local RPC queue
// to push into. Previously the entire flush was skipped when `bindings`
// was empty, but the deltas were still drained off the ring — silently
// discarding session-close/expire events and desynchronizing peers,
// sibling workers, and CLI/gRPC visibility.
// Returns `true` if a correctness-critical HA session open/close delta could
// not be queued losslessly to the event-stream consumer (channel wedged or peer
// disconnected) — #2874. The caller latches loss-of-sync so the worker loop
// re-exports the full owner-RG snapshot (the #2442 recovery path) and the peer
// re-derives a complete session view instead of silently missing the delta.
pub(super) fn flush_session_deltas(
    ident: &BindingIdentity,
    live: Option<&BindingLiveState>,
    session_map_fd: c_int,
    conntrack_v4_fd: c_int,
    conntrack_v6_fd: c_int,
    // #2979: the reverse-NAT dnat_table / dnat_table_v6 fds so a closing SNAT
    // session's published reverse-NAT entry is deleted here, mirroring the
    // session_map / conntrack cleanup below. Without it the HASH (non-LRU)
    // dnat_table leaks one entry per closed SNAT session until it fills.
    dnat_fds: &super::checksum::DnatTableFds,
    deltas: &[SessionDelta],
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_nat_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_forward_wire_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    shared_owner_rg_indexes: &SharedSessionOwnerRgIndexes,
    recent_session_deltas: &Arc<Mutex<VecDeque<SessionDeltaInfo>>>,
    peer_worker_commands: &[Arc<Mutex<VecDeque<WorkerCommand>>>],
    event_stream: &Option<crate::event_stream::EventStreamWorkerHandle>,
    forwarding: &ForwardingState,
) -> bool {
    let zone_name_to_id = &forwarding.zone_name_to_id;
    let zone_id_to_name = &forwarding.zone_id_to_name;
    // #2874: set the moment a session open/close delta cannot be queued
    // losslessly to the event-stream consumer. Once set we stop attempting
    // further lossless pushes this batch — the full owner-RG resync the caller
    // schedules supersedes the remaining incremental deltas, and this bounds the
    // worst-case producer backpressure to a single lossless wait per drain
    // cycle even when the consumer is genuinely wedged.
    let mut event_stream_out_of_sync = false;
    for delta in deltas {
        // #919/#922: emit both the resolved zone NAMES (legacy field,
        // empty when the ID is unknown) and the u16 IDs. New daemons
        // prefer the IDs; older daemons read the names. The previous
        // code wrote `metadata.ingress_zone.to_string()` here, which
        // produced "1"/"2" string literals that broke `zoneIDs[name]`
        // on the Go side.
        let ingress_name = zone_id_to_name
            .get(&delta.metadata.ingress_zone)
            .cloned()
            .unwrap_or_default();
        let egress_name = zone_id_to_name
            .get(&delta.metadata.egress_zone)
            .cloned()
            .unwrap_or_default();
        let info = SessionDeltaInfo {
            timestamp: Utc::now(),
            slot: ident.slot,
            queue_id: ident.queue_id,
            worker_id: ident.worker_id,
            interface: ident.interface.to_string(),
            ifindex: ident.ifindex,
            event: session_delta_event(delta.kind).to_string(),
            addr_family: delta.key.addr_family,
            protocol: delta.key.protocol,
            src_ip: delta.key.src_ip.to_string(),
            dst_ip: delta.key.dst_ip.to_string(),
            src_port: delta.key.src_port,
            dst_port: delta.key.dst_port,
            ingress_zone: ingress_name,
            egress_zone: egress_name,
            ingress_zone_id: delta.metadata.ingress_zone,
            egress_zone_id: delta.metadata.egress_zone,
            owner_rg_id: delta.metadata.owner_rg_id,
            disposition: match delta.decision.resolution.disposition {
                ForwardingDisposition::ForwardCandidate => "forward_candidate",
                ForwardingDisposition::LocalDelivery => "local_delivery",
                ForwardingDisposition::NoRoute => "no_route",
                ForwardingDisposition::MissingNeighbor => "missing_neighbor",
                ForwardingDisposition::PolicyDenied => "policy_denied",
                ForwardingDisposition::FabricRedirect => "fabric_redirect",
                ForwardingDisposition::HAInactive => "ha_inactive",
                ForwardingDisposition::DiscardRoute => "discard_route",
                ForwardingDisposition::NextTableUnsupported => "next_table_unsupported",
            }
            .to_string(),
            origin: delta.origin.as_str().to_string(),
            egress_ifindex: delta.decision.resolution.egress_ifindex,
            tx_ifindex: delta.decision.resolution.tx_ifindex,
            tunnel_endpoint_id: delta.decision.resolution.tunnel_endpoint_id,
            tx_vlan_id: delta.decision.resolution.tx_vlan_id,
            next_hop: delta
                .decision
                .resolution
                .next_hop
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            neighbor_mac: delta
                .decision
                .resolution
                .neighbor_mac
                .map(format_mac)
                .unwrap_or_default(),
            src_mac: delta
                .decision
                .resolution
                .src_mac
                .map(format_mac)
                .unwrap_or_default(),
            nat_src_ip: delta
                .decision
                .nat
                .rewrite_src
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            nat_dst_ip: delta
                .decision
                .nat
                .rewrite_dst
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            nat_src_port: delta.decision.nat.rewrite_src_port.unwrap_or(0),
            nat_dst_port: delta.decision.nat.rewrite_dst_port.unwrap_or(0),
            fabric_redirect: delta.fabric_redirect_sync
                || delta.decision.resolution.disposition == ForwardingDisposition::FabricRedirect,
            fabric_ingress: delta.metadata.fabric_ingress,
            // #2785: carry the per-policy log selection on the JSON fallback
            // delta so the synced session logs identically after failover.
            log_session_init: delta.metadata.log_session_init,
            log_session_close: delta.metadata.log_session_close,
        };
        // #2669: per-binding RPC fallback push is the ONLY binding-dependent
        // step. Skipped when no binding exists; every consumer below is
        // binding-independent and runs regardless.
        if let Some(live) = live {
            live.push_session_delta(info.clone());
        }
        // Push to event stream (new path) alongside existing RPC fallback.
        if let Some(es) = event_stream {
            // #2874: route the correctness-critical HA session open/close delta
            // through the LOSSLESS producer instead of the lossy `push_delta`.
            // `push_delta`'s `try_send` silently drops on a full channel AFTER
            // burning a sequence number, leaving a hole the Go consumer then
            // cumulatively ACKs past — permanently trimming the helper replay
            // window over a missing open/close (silent standby session loss,
            // the #2874 defect). `push_delta_lossless` applies the producer's
            // bounded backpressure and PROPAGATES a genuine failure (peer
            // disconnect / queue timeout) as an error instead of swallowing it.
            // On failure we latch out-of-sync; the caller then re-exports the
            // full owner-RG snapshot (the #2442 recovery path) so the peer
            // re-derives a complete session view. The RT_FLOW telemetry frames
            // below stay best-effort (`try_send`) — a dropped flow-export record
            // is not a correctness loss and must not force a resync.
            if !event_stream_out_of_sync {
                if let Err(err) = es.push_delta_lossless(delta, zone_name_to_id) {
                    event_stream_out_of_sync = true;
                    eprintln!(
                        "xpf-event-stream: HA session-sync delta could not be queued losslessly ({err}); latching out-of-sync to force a full owner-RG resync"
                    );
                }
            }
            // #2460: a Close delta also emits a SEPARATE RT_FLOW
            // SESSION_CLOSE frame (type 14) on the raw dataplane-event
            // channel. `push_delta` above already sent the type-2 HA
            // session-sync close delta unchanged; this is ADDITIVE and
            // feeds the Go NetFlow/IPFIX session-close exporters, which only
            // fire on a `Type == "SESSION_CLOSE"` EventRecord (never
            // produced in userspace mode before this). The two frames are a
            // 1:1 pair per close — no double-counting on the HA channel.
            if delta.kind == SessionDeltaKind::Close {
                // #2520: resolve the AppID for the closing 5-tuple with the
                // SAME app_catalog the forwarding hot path runs, so the
                // SESSION_CLOSE RT_FLOW record carries the application instead
                // of UNKNOWN. 0 (no match) keeps the prior UNKNOWN rendering.
                // #3321: resolve directionally off the delta's own direction
                // flag (service = dst forward / src reverse) so a forward flow
                // with a service-valued source port is not mislabeled.
                // #3416: resolve the FORWARD service port from the
                // post-translation destination (the DNAT-rewritten port the
                // policy admitted the session under), mirroring the deny side,
                // so a port-forwarded service is not mislabeled UNKNOWN/public.
                let app_id = forwarding.app_catalog.lookup_admitted(
                    delta.key.protocol,
                    delta.key.src_port,
                    delta.key.dst_port,
                    delta.metadata.is_reverse,
                    delta.decision.nat.rewrite_dst_port,
                );
                // #2615: thread the closing binding's ingress ifindex so the
                // SESSION_CLOSE RT_FLOW record shows the admitting interface
                // (`packet-incoming-interface`) instead of "N/A". `ident` is
                // the binding draining this delta; its ifindex is the ingress
                // interface. A kernel ifindex is always positive, so the
                // i32 -> u32 cast is loss-free.
                es.emit_session_close_rt_flow(delta, app_id, ident.ifindex as u32);
            }
            // #2508: a session admitted by a policy configured with
            // `then log session-init` emits an RT_FLOW SESSION_CREATE frame
            // (type 15) on the same raw dataplane-event channel. Unlike the
            // close frame this is producer-gated: there is no flowexport
            // consumer of session opens, so we only ever send it when the
            // admitting policy requested session-init logging. The
            // SESSION_CLOSE syslog record is gated on the Go side (via the
            // frame's gate byte) because flowexport still needs every close.
            if delta.kind == SessionDeltaKind::Open && delta.metadata.log_session_init {
                // #2615: resolve the AppID for the new 5-tuple with the SAME
                // app_catalog the forwarding hot path runs (mirroring the #2520
                // close-side fix), so the SESSION_CREATE RT_FLOW record carries
                // the application instead of UNKNOWN. 0 (no match) keeps the
                // prior UNKNOWN rendering. The ingress ifindex comes from the
                // admitting binding (`ident`); a kernel ifindex is always
                // positive so the i32 -> u32 cast is loss-free.
                // #3321: directional resolution off the delta's direction flag
                // (service = dst forward / src reverse).
                // #3416: forward service port from the post-translation
                // (DNAT-rewritten) destination — the port the policy admitted
                // the session under — so a port-forwarded create record carries
                // the admitting application instead of UNKNOWN/the public port.
                let app_id = forwarding.app_catalog.lookup_admitted(
                    delta.key.protocol,
                    delta.key.src_port,
                    delta.key.dst_port,
                    delta.metadata.is_reverse,
                    delta.decision.nat.rewrite_dst_port,
                );
                es.emit_session_create_rt_flow(delta, app_id, ident.ifindex as u32);
            }
        }
        if let Ok(mut recent) = recent_session_deltas.lock() {
            push_recent_session_delta(&mut recent, info);
        }
        if delta.kind == SessionDeltaKind::Close {
            if cfg!(feature = "debug-log") {
                debug_log!(
                    "SESS_DELETE: proto={} {}:{} -> {}:{} nat_src={:?} nat_dst={:?} bpf_entries_before={}",
                    delta.key.protocol,
                    delta.key.src_ip,
                    delta.key.src_port,
                    delta.key.dst_ip,
                    delta.key.dst_port,
                    delta.decision.nat.rewrite_src,
                    delta.decision.nat.rewrite_dst,
                    count_bpf_session_entries(session_map_fd),
                );
            }
            delete_live_session_entry(
                session_map_fd,
                &delta.key,
                delta.decision.nat,
                delta.metadata.is_reverse,
            );
            delete_bpf_conntrack_entry(conntrack_v4_fd, conntrack_v6_fd, &delta.key);
            // #2979: delete the dynamic reverse-NAT dnat_table entry this
            // SNAT'd session published at install. Keyed on the SAME forward
            // key + nat decision used by publish_dnat_table_entry (the Close
            // delta carries the forward key — it is gated on !is_reverse at
            // construction in session/expire.rs and session/mod.rs). A
            // non-SNAT session is a no-op (no rewrite_src -> no key). Only the
            // forward key publishes a dnat_table entry, so it is NOT repeated
            // for the reverse key below.
            super::checksum::delete_dnat_table_entry(dnat_fds, &delta.key, delta.decision.nat);
            remove_shared_session(
                shared_sessions,
                shared_nat_sessions,
                shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                &delta.key,
            );
            let reverse_key = reverse_session_key(&delta.key, delta.decision.nat);
            delete_live_session_entry(session_map_fd, &reverse_key, delta.decision.nat, true);
            delete_bpf_conntrack_entry(conntrack_v4_fd, conntrack_v6_fd, &reverse_key);
            remove_shared_session(
                shared_sessions,
                shared_nat_sessions,
                shared_forward_wire_sessions,
                &shared_owner_rg_indexes,
                &reverse_key,
            );
            replicate_session_delete(peer_worker_commands, &delta.key);
            // #1069: reuse the reverse_key already computed above instead of
            // recomputing it. reverse_session_key is pure on its inputs and
            // delta + nat are not modified between the two replicate calls.
            replicate_session_delete(peer_worker_commands, &reverse_key);
            if cfg!(feature = "debug-log") {
                debug_log!(
                    "SESS_DELETE_DONE: bpf_entries_after={}",
                    count_bpf_session_entries(session_map_fd),
                );
            }
        }
    }
    event_stream_out_of_sync
}

fn session_delta_event(kind: SessionDeltaKind) -> &'static str {
    match kind {
        SessionDeltaKind::Open => "open",
        SessionDeltaKind::Close => "close",
    }
}
