use super::super::*;

/// #6211: resolve the ACTIVE node's `(from_zone, to_zone)` NAME pair for a
/// synced session, so the standby's source-NAT reservation lands on the rule
/// the active actually matched rather than on the first rule whose pool merely
/// CONTAINS the translated address (which diverges when two rules carry
/// overlapping pool addresses in separate allocators).
///
/// The IDs come off the HA session-sync wire (`SessionSyncRequest`'s
/// `ingress_zone_id`/`egress_zone_id`, with the legacy name strings resolved
/// through `zone_name_to_id` for an older peer — see
/// `build_synced_session_entry`), so this is a pure local lookup: no new wire
/// field, and an old peer degrades to `None`.
///
/// `None` whenever EITHER side fails to resolve to a non-empty local zone name
/// — an unknown/dropped zone, or config drift between the nodes. `populate_zones`
/// never admits id 0 or an empty name, but the emptiness check is enforced here
/// too rather than assumed: an empty `from_zone` would silently EXCLUDE every
/// zone-scoped rule instead of leaving the axis unconstrained, which is the one
/// way this narrowing could pick a worse rule than the pre-#6211 fallback.
/// #6600: `pub(in crate::afxdp)` so the COORDINATOR's pre-publish reservation
/// resolves the zone pair through the SAME function the worker does. If the two
/// ever disagreed, the coordinator would reserve on one allocator and the worker
/// on another — the coordinator's check would pass while the port the session
/// actually names stayed unreserved, which is the defect wearing a new shape.
pub(in crate::afxdp) fn synced_source_nat_zone_pair<'a>(
    forwarding: &'a ForwardingState,
    metadata: &crate::session::SessionMetadata,
) -> crate::nat::SyncedNatZones<'a> {
    let from = forwarding.zone_id_to_name.get(&metadata.ingress_zone)?;
    let to = forwarding.zone_id_to_name.get(&metadata.egress_zone)?;
    (!from.is_empty() && !to.is_empty()).then_some((from.as_str(), to.as_str()))
}

/// Apply `WorkerCommand::UpsertSynced`: re-resolve the synced
/// forward session with local egress (regardless of HA state — #326),
/// upsert into the session table, and publish the kernel session-map
/// entry if the upsert took.
///
/// Lifted verbatim from `apply_worker_commands` at the
/// `WorkerCommand::UpsertSynced` match arm.
///
/// Synced sessions arrive with the remote node's interface indices
/// and MACs which don't work on this node. By resolving on receipt
/// (even on standby), sessions are immediately forwarding-ready at
/// activation — the helper no longer needs a second activation-time
/// forward scan to fix them up. HA enforcement still happens at
/// packet time via flow cache validation
/// (`enforce_ha_resolution_snapshot`).
pub(in crate::afxdp::session_glue) fn handle_upsert_synced(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    mut entry: SyncedSessionEntry,
    now_ns: u64,
    now_secs: u64,
    // #6211 F2: THIS worker's id, from `WorkerLaunchPlan::worker_id` via
    // `apply_worker_commands`. The synced entry is fanned out to every worker,
    // so the reservation below must record which worker took it.
    worker_id: u32,
) {
    let key = entry.key.clone();
    let allow_replace_local =
        synced_entry_allows_local_replace(ha_state, entry.metadata.owner_rg_id, now_secs);
    let is_active = !allow_replace_local;

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
        // On active node, enforce HA snapshot to filter out sessions
        // for inactive RGs. On standby, skip HA enforcement — store
        // the resolved ForwardCandidate so the session is ready when
        // activation happens. The packet path enforces HA state via
        // flow cache validation.
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
        SessionInstall {
            key: entry.key,
            decision: entry.decision,
            metadata: entry.metadata,
            origin: entry.origin,
            now_ns,
            protocol: entry.protocol,
            tcp_flags: entry.tcp_flags,
            // #5212: carry the peer's stable RT_FLOW id from the synced entry so
            // the standby ADOPTS it (non-zero on a wire import; 0 => local alloc).
            session_id: entry.session_id,
        },
        allow_replace_local,
    ) {
        // #4388: reserve the synced session's translated NAT pool port in this
        // node's LOCAL source-NAT allocator. The standby imports the active
        // node's pre-computed NAT decision but never runs `allocate_translation`,
        // so without this its allocator does not know `(pool_addr, port)` is in
        // use — post-failover a new local flow could reuse it, colliding two
        // sessions on one NAT source tuple. Only forward, peer-synced entries
        // reserve (a reverse entry carries the destination rewrite, not the
        // pool source port; a local-origin entry already allocated its port on
        // the active path). The reservation is freed by the standard teardown
        // (`release_source_nat_allocation`) on reap or delete-sync.
        if entry.origin.is_peer_synced() && !metadata.is_reverse {
            reserve_synced_source_nat_allocation_for_worker(
                &forwarding.iface_nat_allocators,
                &forwarding.source_nat_rules,
                &key,
                entry.decision.nat,
                metadata.is_reverse,
                // #6211: the active's zone pair, so the reservation lands in
                // the allocator the active used when two rules share a pool
                // address. `None` (old peer / unknown zone) keeps the
                // pre-#6211 first-pool-match.
                synced_source_nat_zone_pair(forwarding, &metadata),
                // #6528: the stale-tuple eviction inside `reserve_flow` retires
                // the incumbent with release semantics; a persistent lease that
                // falls to zero active flows re-arms its idle expiry off this
                // clock.
                now_ns,
                // #6211 F2: record this worker as a HOLDER. Every worker
                // reserves the same `(flow, translated)` against ONE shared
                // allocator; without the holder bit the first worker to reap or
                // delete-sync frees a port the others still forward through.
                worker_id,
            );
            // #4512: same treatment for NAT64. The translated `(pool v4, port)`
            // rides the synced `NatDecision` (`rewrite_src_port`), but the
            // standby never runs `allocate_source`, so without this its NAT64
            // allocator does not know the port is in use — post-failover a
            // fresh local NAT64 flow could reuse it, two flows colliding on one
            // translated source (RFC 6146 BIB violation across a cross-node
            // failover). No-op for a non-NAT64 decision. Freed by the same
            // `release_nat64_allocation` on reap / delete-sync.
            crate::nat64::reserve_synced_nat64_allocation_for_worker(
                &forwarding.nat64,
                &key,
                entry.decision.nat,
                metadata.is_reverse,
                // #6528: same clock, same reason as the source-NAT reserve.
                now_ns,
                worker_id,
            );
        }
        publish_worker_session_map_entry(
            session_map_fd,
            forwarding,
            &key,
            entry.decision,
            &metadata,
            entry.origin,
            allow_replace_local,
        );
    }
}
