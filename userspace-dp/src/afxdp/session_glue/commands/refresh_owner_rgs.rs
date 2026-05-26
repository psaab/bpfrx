use super::super::*;

/// Apply `WorkerCommand::RefreshOwnerRGS`: re-evaluate every
/// HA-managed worker session (not just those currently indexed under
/// the activated RG) and republish refreshed session-map entries.
///
/// Lifted verbatim from `apply_worker_commands` at the
/// `WorkerCommand::RefreshOwnerRGS` match arm. The wider scan handles
/// split-RG reverse companions that can remain owned by RG2 while a
/// move of RG1 changes whether they should locally forward or
/// fabric-redirect.
pub(in crate::afxdp::session_glue) fn handle_refresh_owner_rgs(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    owner_rgs: Vec<i32>,
    now_ns: u64,
    now_secs: u64,
) {
    if !owner_rgs.iter().any(|owner_rg_id| *owner_rg_id > 0) {
        return;
    }

    // Activation must re-evaluate all HA-managed worker sessions, not
    // just those currently indexed under the activated RG. Split-RG
    // reverse companions can remain owned by RG2 while a move of RG1
    // changes whether they should locally forward or fabric-redirect.
    // Activation is infrequent, so do the wider worker scan here
    // instead of trusting potentially stale RG ownership buckets.
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
        let looked_up_resolution =
            lookup_forwarding_resolution_for_session(forwarding, dynamic_neighbors, &flow, decision);
        let looked_up_resolution = super::super::prefer_local_forward_candidate_for_fabric_ingress(
            forwarding,
            ha_state,
            dynamic_neighbors,
            now_secs,
            metadata.fabric_ingress,
            resolution_target,
            looked_up_resolution,
        );
        let enforced_resolution =
            enforce_ha_resolution_snapshot(forwarding, ha_state, now_secs, looked_up_resolution);
        let refreshed_decision = SessionDecision {
            resolution: redirect_session_via_fabric_if_needed(
                forwarding,
                enforced_resolution,
                metadata.fabric_ingress,
                metadata.ingress_zone,
            ),
            ..decision
        };
        let mut refreshed_metadata = metadata.clone();
        let refreshed_owner_rg = owner_rg_for_resolution(forwarding, refreshed_decision.resolution);
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
                forwarding,
                &key,
                refreshed_decision,
                &refreshed_metadata,
                origin,
                false,
            );
        }
    }
}
