// Forward/reverse tuple match logic (#2005 pure code-motion split of
// session/mod.rs). The read-path conntrack lookups that resolve a wire
// or translated tuple back to an installed session live here: the
// primary/alias `lookup` family, the NAT/wire reverse-match finders, the
// single-entry/owner-RG/iteration read accessors, and `take_synced_local`
// (the HA local-take, which is a lookup that consumes on hit). Bodies are
// byte-for-byte identical to the prior in-`mod.rs` form; this file only
// changes the module boundary. All methods retain their original `pub`
// visibility (they hang off the `pub(crate)` SessionTable type and are
// callable crate-wide). No visibility was widened here: the private
// helpers these methods call (`entry_by_key`, `remove_entry`,
// `session_timeout_ns`, the wire-key transforms) live in ancestor
// modules and are visible to this descendant.

use super::*;

impl SessionTable {
    pub fn lookup(
        &mut self,
        key: &SessionKey,
        now_ns: u64,
        tcp_flags: u8,
    ) -> Option<SessionLookup> {
        self.lookup_with_origin(key, now_ns, tcp_flags)
            .map(|(lookup, _origin)| lookup)
    }

    pub fn lookup_with_origin(
        &mut self,
        key: &SessionKey,
        now_ns: u64,
        tcp_flags: u8,
    ) -> Option<(SessionLookup, SessionOrigin)> {
        // #964 Step 1: resolve handle from key. Direct-primary path
        // looks up via key_to_handle; alias path (NAT-translated
        // reverse key) goes via reverse_translated_index.
        let (handle, via_alias) = match self.key_to_handle.get(key) {
            Some(h) => (*h, false),
            None => match self.reverse_translated_index.get(key) {
                Some(h) => (*h, true),
                None => return None,
            },
        };
        // Pre-compute the timeout before borrowing &mut self.entries
        // so the inner block doesn't need to access self.timeouts.
        let timeouts = self.timeouts;
        // Scope the &mut self.entries borrow so it ends BEFORE we
        // touch self.wheel via push_to_wheel. Without this scoping
        // the &mut record would conflict with the second &mut self
        // via self.wheel.
        let (result, actual_key) = {
            let record = self.entries.get_mut(handle as usize)?;
            // #964 Step 1: path-specific validation defends against
            // a stale secondary index pointing at a slab slot that
            // was reused by a different session (release-mode guard,
            // not just debug). Direct-primary checks record.key ==
            // *key; alias path verifies the NAT-translation roundtrip.
            if !via_alias {
                if record.key != *key {
                    return None;
                }
            } else {
                let must_be_reverse = record.entry.metadata.is_reverse;
                let translated = translated_session_key(&record.key, record.entry.decision.nat);
                if !must_be_reverse || translated != *key {
                    return None;
                }
            }
            let entry = &mut record.entry;
            if matches!(key.protocol, PROTO_TCP) && is_closing(tcp_flags) {
                if !entry.closing {
                    debug_log!(
                        "SESS_CLOSING: {} proto=TCP {}:{} -> {}:{} rev={} tcp_flags=0x{:02x}",
                        if has_rst(tcp_flags) {
                            "RST"
                        } else {
                            "FIN"
                        },
                        key.src_ip,
                        key.src_port,
                        key.dst_ip,
                        key.dst_port,
                        entry.metadata.is_reverse,
                        tcp_flags,
                    );
                }
                entry.closing = true;
            }
            entry.last_seen_ns = now_ns;
            entry.expires_after_ns = if matches!(key.protocol, PROTO_TCP) && entry.closing {
                TCP_CLOSING_TIMEOUT_NS
            } else {
                session_timeout_ns(key.protocol, tcp_flags, &timeouts)
            };
            (
                (
                    SessionLookup {
                        decision: entry.decision,
                        metadata: entry.metadata.clone(),
                    },
                    entry.origin,
                ),
                record.key.clone(),
            )
        }; // <-- &mut self.entries borrow ends here
        // Push the canonical key (NOT the alias lookup `key`) into
        // the wheel. push_to_wheel re-reads the record to compute
        // the throttled target_tick — that matches the model in the
        // plan (~100 ns per FxHashMap lookup on the slow path).
        self.push_to_wheel(&actual_key, now_ns);
        Some(result)
    }

    pub fn find_forward_nat_match(&self, reply_key: &SessionKey) -> Option<ForwardSessionMatch> {
        let handle = *self.nat_reverse_index.get(reply_key)?;
        let record = self.entries.get(handle as usize)?;
        let entry = &record.entry;
        if entry.metadata.is_reverse
            || !reply_matches_forward_session(&record.key, entry.decision.nat, reply_key)
        {
            return None;
        }
        Some(ForwardSessionMatch {
            key: record.key.clone(),
            decision: entry.decision,
            metadata: entry.metadata.clone(),
        })
    }

    pub fn find_forward_wire_match(&self, wire_key: &SessionKey) -> Option<ForwardSessionMatch> {
        self.find_forward_wire_match_with_origin(wire_key)
            .map(|(matched, _origin)| matched)
    }

    pub fn find_forward_wire_match_with_origin(
        &self,
        wire_key: &SessionKey,
    ) -> Option<(ForwardSessionMatch, SessionOrigin)> {
        let handle = *self.forward_wire_index.get(wire_key)?;
        let record = self.entries.get(handle as usize)?;
        let entry = &record.entry;
        if entry.metadata.is_reverse
            || forward_wire_key(&record.key, entry.decision.nat) != *wire_key
        {
            return None;
        }
        Some((
            ForwardSessionMatch {
                key: record.key.clone(),
                decision: entry.decision,
                metadata: entry.metadata.clone(),
            },
            entry.origin,
        ))
    }

    pub fn entry_with_origin(
        &self,
        key: &SessionKey,
    ) -> Option<(SessionDecision, SessionMetadata, SessionOrigin)> {
        self.entry_by_key(key)
            .map(|entry| (entry.decision, entry.metadata.clone(), entry.origin))
    }

    /// #2442: every owner-RG id that currently indexes at least one session in
    /// this worker's table. Used by the loss-of-sync resync path to export ALL
    /// owned forward sessions (the same RG set
    /// `export_forward_sessions_for_owner_rgs` would walk) without needing the
    /// coordinator's RG runtime view — the table's own `owner_rg_sessions`
    /// index is the ground truth for what this worker owns. Empty sets are
    /// skipped (an owner RG can transiently hold a now-empty index entry).
    pub fn all_owner_rg_ids(&self) -> Vec<i32> {
        self.owner_rg_sessions
            .iter()
            .filter(|(_, set)| !set.is_empty())
            .map(|(rg, _)| *rg)
            .collect()
    }

    pub fn owner_rg_session_keys(&self, owner_rgs: &[i32]) -> Vec<SessionKey> {
        // #964 Step 1: handles → keys via the slab. Each session is
        // in at most one owner-RG set, so total iteration is
        // O(owner-sessions), same complexity as today's key-based
        // index returned.
        let mut handles: FxHashSet<u32> = FxHashSet::default();
        for owner_rg_id in owner_rgs {
            if let Some(set) = self.owner_rg_sessions.get(owner_rg_id) {
                handles.extend(set.iter().copied());
            }
        }
        handles
            .into_iter()
            .filter_map(|h| self.entries.get(h as usize).map(|r| r.key.clone()))
            .collect()
    }

    pub fn take_synced_local(&mut self, key: &SessionKey) -> Option<SessionLookup> {
        let entry = self.entry_by_key(key)?;
        if !entry.origin.is_peer_synced()
            || entry.metadata.is_reverse
            || entry.decision.resolution.disposition != ForwardingDisposition::LocalDelivery
        {
            return None;
        }
        self.remove_entry(key).map(|entry| SessionLookup {
            decision: entry.decision,
            metadata: entry.metadata,
        })
    }

    pub fn iter_with_origin(
        &self,
        mut f: impl FnMut(&SessionKey, SessionDecision, &SessionMetadata, SessionOrigin),
    ) {
        // Walk via key_to_handle (the primary index) so any orphan
        // slab record without a forward-key mapping is skipped —
        // matches the plan's "primary index is authoritative" model.
        for (key, handle) in &self.key_to_handle {
            if let Some(record) = self.entries.get(*handle as usize) {
                f(
                    key,
                    record.entry.decision,
                    &record.entry.metadata,
                    record.entry.origin,
                );
            }
        }
    }

    /// Iterate over all session entries with idle time (in nanoseconds).
    pub fn iter_with_idle(
        &self,
        now_ns: u64,
        mut f: impl FnMut(&SessionKey, SessionDecision, &SessionMetadata, u64),
    ) {
        self.iter_with_idle_and_origin(now_ns, |key, decision, metadata, _origin, idle_ns| {
            f(key, decision, metadata, idle_ns)
        });
    }

    pub fn iter_with_idle_and_origin(
        &self,
        now_ns: u64,
        mut f: impl FnMut(&SessionKey, SessionDecision, &SessionMetadata, SessionOrigin, u64),
    ) {
        for (key, handle) in &self.key_to_handle {
            if let Some(record) = self.entries.get(*handle as usize) {
                let entry = &record.entry;
                let idle_ns = now_ns.saturating_sub(entry.last_seen_ns);
                f(key, entry.decision, &entry.metadata, entry.origin, idle_ns);
            }
        }
    }
}
