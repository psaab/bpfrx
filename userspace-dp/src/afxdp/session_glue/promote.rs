use super::*;

/// Shared-session backing references that travel together at every
/// site that touches synced sessions. Grouping them collapses the
/// 16-param `maybe_promote_synced_session` and 10-param
/// `purge_translated_synced_hit` signatures that triggered #1346.
/// (Issue body rounded these to 17/11 by counting `&mut sessions`
/// as a leading param; the actual `fn` declarations on
/// `origin/master` carry 16 and 10 typed args respectively.)
///
/// `Copy` because the struct is 4 `&`-references (= 32 bytes on
/// x86-64) with no destructor. Passing it by value at the 3 call
/// sites in `resolve_flow_session_decision` should compile to the
/// same register/stack use vs. passing the 4 references
/// individually. Note: `cargo-asm 0.1.16` panics parsing this
/// codebase's symbols, so a programmatic before/after asm diff was
/// not produced. The zero-cost claim rests on the structural
/// argument (Copy + pointer-sized fields + no Drop) and is
/// empirically gated by the smoke-plus-test-failover pass in the PR.
#[derive(Clone, Copy)]
pub(in crate::afxdp::session_glue) struct SharedSessionRefs<'a> {
    pub sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub nat_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub forward_wire_sessions: &'a Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    pub owner_rg_indexes: &'a SharedSessionOwnerRgIndexes,
}

/// Predicate: is `key` the forward (NAT-translated) side of a
/// synced session? Used to distinguish translated forward hits from
/// reverse-side hits when deciding whether to purge a transient
/// peer-synced entry.
pub(in crate::afxdp::session_glue) fn is_translated_forward_session_key(
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
) -> bool {
    if metadata.is_reverse {
        return false;
    }
    decision.nat.rewrite_src == Some(key.src_ip) || decision.nat.rewrite_dst == Some(key.dst_ip)
}

/// Predicate: should a peer-synced hit be kept as transient (i.e.
/// purged from the shared maps so the local node re-resolves) rather
/// than being installed locally? True when the local node is not the
/// active owner of the session's RG and the key is the translated
/// forward side.
pub(in crate::afxdp::session_glue) fn should_keep_synced_hit_transient(
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

/// Promote a synced session hit into a locally-owned session when
/// the local node is now the active owner. No-op if the session is
/// not promotable or not currently in a `ForwardCandidate` state.
///
/// On successful promotion, the session is re-published to the
/// kernel session map, mirrored into the shared maps under
/// `SharedPromote` origin, and replicated to peer worker commands.
///
/// Behavior unchanged from the pre-#1346 free function; only the
/// signature changed (16 → 13 params via `SharedSessionRefs`).
pub(in crate::afxdp::session_glue) fn maybe_promote_synced_session(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    shared: SharedSessionRefs<'_>,
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
    if sessions.promote_synced_with_origin(SessionUpdate {
        key,
        decision,
        metadata: promoted.clone(),
        origin: SessionOrigin::SharedPromote,
        now_ns,
        protocol,
        tcp_flags,
    }) {
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
            shared.sessions,
            shared.nat_sessions,
            shared.forward_wire_sessions,
            shared.owner_rg_indexes,
            &promoted_entry,
        );
        replicate_session_upsert(peer_worker_commands, &promoted_entry);
    }
    promoted
}

/// Purge a translated peer-synced hit: drop the entry from the shared
/// maps, delete the kernel session-map entry, and remove the local
/// session-table entry. Used when the local node is not the active
/// owner of a translated forward session — leaving the hit live would
/// route traffic to the wrong node.
///
/// Behavior unchanged from the pre-#1346 free function; only the
/// signature changed (10 → 7 params via `SharedSessionRefs`).
pub(in crate::afxdp::session_glue) fn purge_translated_synced_hit(
    sessions: &mut SessionTable,
    session_map_fd: c_int,
    shared: SharedSessionRefs<'_>,
    key: &SessionKey,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
) {
    if !origin.is_peer_synced() || !is_translated_forward_session_key(key, decision, metadata) {
        return;
    }
    remove_shared_session(
        shared.sessions,
        shared.nat_sessions,
        shared.forward_wire_sessions,
        shared.owner_rg_indexes,
        key,
    );
    delete_session_map_entry_for_removed_session(session_map_fd, key, decision, metadata);
    sessions.delete(key);
}
