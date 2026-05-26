use super::super::*;

/// Apply `WorkerCommand::DemoteOwnerRGS`: walk each demoted owner RG,
/// re-resolve forwarding for every demoted session, re-publish the
/// kernel session-map entry, and append demoted keys (deduped) to
/// `cancelled_keys`.
///
/// Lifted verbatim from `apply_worker_commands` at the
/// `WorkerCommand::DemoteOwnerRGS` match arm. Takes a narrow
/// `&mut Vec<SessionKey>` because the dispatcher builds the
/// `WorkerCommandResults` accumulator after the loop (per #1346
/// plan v2).
pub(in crate::afxdp::session_glue) fn handle_demote_owner_rgs(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    owner_rgs: Vec<i32>,
    now_ns: u64,
    now_secs: u64,
    cancelled_keys: &mut Vec<SessionKey>,
) {
    let mut seen_owner_rgs = std::collections::BTreeSet::new();
    for owner_rg_id in owner_rgs {
        if !seen_owner_rgs.insert(owner_rg_id) {
            continue;
        }
        for demoted_key in sessions.demote_owner_rg(owner_rg_id) {
            let Some((decision, metadata, _origin)) = sessions.entry_with_origin(&demoted_key)
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
            let rewrote_session = refreshed_decision.resolution.disposition
                != ForwardingDisposition::HAInactive
                && sessions.refresh_for_ha_transition(
                    &demoted_key,
                    refreshed_decision,
                    metadata.clone(),
                    now_ns,
                );
            let Some((decision, metadata, origin)) = sessions.entry_with_origin(&demoted_key)
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
                forwarding,
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
